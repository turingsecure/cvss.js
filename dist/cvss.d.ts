export = CVSS;
/**
 * Creates a new CVSS object
 *
 * @param {String} vector
 */
declare function CVSS(vector: string): {
    vector: string;
    getScore: () => number;
    getTemporalScore: () => number;
    getEnvironmentalScore: () => number;
    getRating: () => string;
    getTemporalRating: () => string;
    getEnvironmentalRating: () => string;
    getVectorObject: () => any;
    getDetailedVectorObject: () => any;
    getVersion: () => string;
    getCleanVectorString: () => string;
    updateVectorValue: (metric: string, value: string) => string;
    isValid: true;
    getImpactSubScore: () => number;
    getExploitabilitySubScore: () => number;
};
