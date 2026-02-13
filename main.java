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
