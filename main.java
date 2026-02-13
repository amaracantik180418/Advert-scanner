import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Advert scanner — Off-chain crawler for advert metadata. Computes crawl windows,
 * batch roots, and source hashes for submission to the AdvertScanner EVM contract.
 */
public final class AdvertScanner {

    public static final String MODULE_NAME = "Advert scanner";
    public static final int CRAWL_WINDOW_BLOCKS = 412;
    public static final int INGEST_BATCH_CAP = 73;
    public static final int MAX_CAMPAIGN_ENTRIES = 511;
    public static final int MIN_SOURCE_BYTES = 8;
    public static final long CRAWL_GRACE_MS = 12_847_293_651L;
    public static final String CONTRACT_HEX = "0x7B2d9E4f6A1c8b0D3e5F7a9C2d4E6b8A0c1D3f5e";
    public static final String DOMAIN_TAG = "advert-scanner-crawl-v1";
    public static final byte SCANNER_VERSION = 0x52;
    public static final String DEPLOY_SALT = "a9e4c1f7b2d8e0a3c6d1f4b7e9a2c5d8f0b3e6a1";

    private final long genesisBlock;
    private final Instant moduleStart;
    private final Map<String, CampaignRecord> campaignCache = new ConcurrentHashMap<>();
    private final Map<Long, IngestBatchRecord> batchCache = new ConcurrentHashMap<>();
    private final Map<Integer, Long> lastCrawlBlockByCategory = new ConcurrentHashMap<>();
    private final AtomicLong nextCampaignId = new AtomicLong(0L);
    private final AtomicLong nextBatchId = new AtomicLong(0L);
    private int crawlCount;
    private int ingestCount;

    public AdvertScanner(long genesisBlock) {
        this.genesisBlock = genesisBlock;
        this.moduleStart = Instant.now();
    }

    /**
     * Next block at which a category is allowed to be crawled (cooldown boundary).
     */
    public long getNextCrawlBlockForCategory(int categoryId) {
        Long last = lastCrawlBlockByCategory.get(categoryId);
        if (last == null) return genesisBlock;
        return last + CRAWL_WINDOW_BLOCKS;
    }

    /**
     * Whether the current block allows a crawl for the given category.
     */
    public boolean canCrawlCategory(int categoryId, long currentBlock) {
        return currentBlock >= getNextCrawlBlockForCategory(categoryId);
    }

    /**
     * Record a campaign discovery locally (mirrors contract discoverCampaign).
     */
    public void discoverCampaignLocal(byte[] sourceHash, int categoryId, long atBlock) {
        String key = sourceHashKey(sourceHash);
        if (campaignCache.containsKey(key)) return;
        long id = nextCampaignId.getAndIncrement();
        campaignCache.put(key, new CampaignRecord(id, sourceHash, categoryId, atBlock, Instant.now(), false));
        lastCrawlBlockByCategory.put(categoryId, atBlock);
        crawlCount++;
    }

    /**
     * Build 32-byte source hash for contract (keccak256(sourcePayload)).
     * Uses SHA-256 here as stand-in; in production use Web3j/keccak.
     */
    public String sourceHashHex(byte[] sourcePayload) {
        if (sourcePayload == null || sourcePayload.length < MIN_SOURCE_BYTES) {
            throw new IllegalArgumentException("Source payload too short");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(sourcePayload);
            return "0x" + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Build batch root from list of campaign ids (keccak256 of ordered ids).
     */
    public String batchRootHex(long[] campaignIds) {
        if (campaignIds == null || campaignIds.length == 0 || campaignIds.length > INGEST_BATCH_CAP) {
            throw new IllegalArgumentException("Invalid campaign id list for batch");
        }
        ByteBuffer buf = ByteBuffer.allocate(campaignIds.length * Long.BYTES);
        for (long id : campaignIds) {
            buf.putLong(id);
        }
        byte[] raw = buf.array();
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw);
            return "0x" + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Register a batch locally (mirrors contract ingestBatch).
     */
    public long registerBatchLocal(String batchRoot, List<Long> campaignIds, long atBlock) {
        if (campaignIds.size() > INGEST_BATCH_CAP) {
            throw new IllegalArgumentException("Batch over cap");
        }
        long id = nextBatchId.getAndIncrement();
        batchCache.put(id, new IngestBatchRecord(id, batchRoot, campaignIds.size(), atBlock, false));
        ingestCount++;
        return id;
    }

    /**
     * Encode calldata selector for discoverCampaign(bytes32,uint16).
     */
    public static String selectorDiscoverCampaign() {
        return "0x" + HexFormat.of().formatHex(selectorBytes("discoverCampaign(bytes32,uint16)"));
    }

    /**
     * Encode calldata selector for ingestBatch(bytes32,uint256[]).
     */
    public static String selectorIngestBatch() {
        return "0x" + HexFormat.of().formatHex(selectorBytes("ingestBatch(bytes32,uint256[])"));
