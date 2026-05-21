import { TRANSLATION_LANGUAGE_KEY, TRANSLATION_LABEL_KEY } from "../core/config.js";

export const state = {
  activeTab: "all",
  currentView: "homepage",
  offset: 0,
  total: 0,
  feedPage: 1,
  feedSnapshots: new Map(),
  feedPrefetchPromises: new Map(),
  feedWarmupPromise: null,
  semanticGuideCache: new Map(),
  paginatedResults: {
    pakdb: { items: [], page: 1 },
    playstore: { items: [], page: 1 },
    software: { items: [], page: 1 }
  },
  credentialPager: {
    query: "",
    page: 1,
    totalPages: 0,
    totalItems: 0
  },
  leakSourceStatus: {
    items: [],
    summary: {}
  },
  healingMonitor: {
    summary: {},
    collectors: [],
    scripts: [],
    events: [],
    selectedScriptId: "",
    scriptDetail: null
  },
  feedFilters: {
    startDate: "",
    endDate: "",
    topic: ""
  },
  feedAbortController: null,
  isRegistering: false,
  authStage: "login",
  authChallengeToken: "",
  authChallengeType: "",
  authPendingUsername: "",
  authPendingRole: "",
  authQrCodeUrl: "",
  authManualSecret: "",
  authLoadingActive: false,
  authLoadingProgress: 0,
  authLoadingCap: 0,
  authLoadingTimer: null,
  semanticSearch: null,
  refreshTimer: null,
  smartUpdateTimer: null,
  mapRefreshTimer: null,
  mapSpotlightTimer: null,
  mapSpotlightIndex: 0,
  mapSpotlightCode: "",
  mapSpotlightCountries: [],
  mapInstance: null,
  detailCache: new Map(),
  countryStatsByCode: {},
  smartUpdatePayload: null,
  smartUpdateJobId: "",
  smartUpdateStatus: "idle",
  headerSearchBusy: false,
  mediaLightboxSrc: "",
  mediaLightboxTitle: "",
  currentDetailItem: null,
  scanExports: {
    pakdb: { query: "", items: [] },
    credential: null,
    playstore: { query: "", items: [] },
    software: { query: "", items: [] },
    seo: null,
    repo: null
  },
  translationLanguage: localStorage.getItem(TRANSLATION_LANGUAGE_KEY) || "en",
  translationLabel: localStorage.getItem(TRANSLATION_LABEL_KEY) || "English",
  translationScope: "view",
  translationCache: new Map()
};
