package main

// BandType represents the wireless band capability of a device
type BandType string

const (
	BandTypeSingleBand BandType = "singleband"
	BandTypeDualBand   BandType = "dualband"
	BandTypeUnknown    BandType = "unknown"
)

// WLAN ID ranges for each band
const (
	// 2.4GHz WLAN IDs (available for all devices)
	WLAN24GHzMin = 1
	WLAN24GHzMax = 4

	// 5GHz WLAN IDs (only available for dual-band devices)
	WLAN5GHzMin = 5
	WLAN5GHzMax = 8
)

// dualBandModels contains all known dual-band ONU models
// Key: model name (case-insensitive matching will be used)
// This list is used to determine if a device supports 5GHz band
var dualBandModels = map[string]bool{
	// ========== Huawei Wi-Fi 6 (OptiXstar - AX Series) ==========
	"EG8145X6": true,
	"HG8145X6": true,
	"HN8145X6": true,
	"EN8145X6": true,
	"K562":     true,
	"K662c":    true,
	"K662C":    true,

	// ========== Huawei Wi-Fi 5 (EchoLife - AC Series) ==========
	"HG8245Q2": true,
	"HG8245Q":  true,
	"HG8145V5": true,
	"EG8145V5": true,
	"HS8546V5": true,
	"HS8145V5": true,
	"HG8245W5": true,
	"EG8141A5": true,
	"WA8021V5": true,
	"HG8247W5": true,

	// ========== ZTE Wi-Fi 7 & Wi-Fi 6 (High End) ==========
	"F8748Q": true, // Wi-Fi 7
	"F6600P": true,
	"F6640":  true,
	"F6610":  true,
	"F6600":  true,
	"F6630":  true,
	"G8605":  true,
	"F2866":  true,

	// ========== ZTE Wi-Fi 5 (AC Series) ==========
	"F670L":   true,
	"F680":    true,
	"F673AV9": true,
	"F609V3":  true,
	"F609 V3": true,
	"F609V4":  true,
	"F609 V4": true,
	"F679D":   true,
	"F670":    true,
	"F660V7":  true,
	"F660 V7": true,
	"F660V9":  true,
	"F660 V9": true,
	"F668":    true,
	"F622C":   true,

	// ========== Fiberhome Dual-Band ==========
	"HG6145D2":     true,
	"HG6143D3":     true,
	"HG6543C":      true,
	"HG6245N":      true,
	"HG6245D":      true,
	"HG6145F":      true,
	"HG6145D":      true,
	"AN5506-04-FA": true,
	"AN550604FA":   true,
	"HG6821M":      true,

	// ========== VSOL Dual-Band (Wi-Fi 6 AX Series) ==========
	"V2804AX15-R":     true,
	"V2804AX15R":      true,
	"V2804AX30T-H":    true,
	"V2804AX30(T)-H":  true,
	"HG3232AX30T-H":   true,
	"HG3232AX30(T)-H": true,
	"V2801AX30C-A":    true,
	"V2804AX30T-A":    true,
	"V2804AX30(T)-A":  true,
	"HG3232AX30T":     true,
	"HG3232AX30(T)":   true,
	"HG3110AX":        true,
	"V2904AX":         true,
	"V2804AX":         true,
	"V2804AX15T":      true,
	"HG325AX":         true,
	"HG325AX15T":      true,
	"HG325DAC":        true,

	// ========== VSOL Dual-Band (Wi-Fi 5 AC Series) ==========
	"V2802AC-H":    true,
	"V2802ACH":     true,
	"V2804ACT-A":   true,
	"V2804AC(T)-A": true,
	"HG325ACT-A":   true,
	"HG325AC(T)-A": true,
	"HG325ACT":     true,
	"HG325AC":      true,
	"V2802AC-B":    true,
	"V2802ACB":     true,
	"HG3221D":      true,
	"HG323AC-B":    true,
	"HG323ACB":     true,
	"HG323ACT":     true,
	"HG323DAC":     true,
	"V2802DAC":     true,
	"V2802ACT":     true,
	"V2804AC-Z":    true,
	"V2804ACZ":     true,
	"V2804ACT":     true,
	"V2804AC":      true,
	"ICT3310D":     true,

	// ========== C-Data Dual-Band ==========
	"FD514GS3-R850": true,
	"FD514GS3R850":  true,
	"FD514GS1-R550": true,
	"FD514GS1R550":  true,
	"FD514GD":       true,
	"FD514GD-R460":  true,
	"FD514GDR460":   true,
	"FD604GW":       true,
	"FD604GW-DX":    true,
	"FD604GWDX":     true,
	"FD512GD":       true,
	"FD512GD-R550":  true,
	"FD512GDR550":   true,
	"FD511GD":       true,
	"FD511GD-F550":  true,
	"FD511GDF550":   true,
	"FD704GD":       true,

	// ========== Zimmlink Dual-Band ==========
	"ZL-4224X": true,
	"ZL4224X":  true,

	// ========== Nokia / Alcatel-Lucent Dual-Band ==========
	"G-2426G-A":  true,
	"G2426GA":    true,
	"G-2425G-B":  true,
	"G2425GB":    true,
	"XS-2426G-A": true,
	"XS2426GA":   true,
	"G-2425G-A":  true,
	"G2425GA":    true,
	"G-240W-F":   true,
	"G240WF":     true,
	"G-240W-C":   true,
	"G240WC":     true,
	"G-140W-C":   true,
	"G140WC":     true,

	// ========== Other / Misc Dual-Band ==========
	"GP1704-2G-22A": true,
	"GP17042G22A":   true,
	"GP1704-4G-22A": true,
	"GP17044G22A":   true,
	"GN542":         true,
	"RN560":         true,
	"UF-WIFI6":      true,
	"UFWIFI6":       true,
	"RL842GW":       true,
}

// singleBandModels contains all known single-band ONU models (2.4GHz only)
var singleBandModels = map[string]bool{
	// ========== Huawei Wi-Fi 4 (EchoLife - N Series) ==========
	"HG8245H":  true,
	"HG8245H5": true,
	"HG8546M":  true,
	"HS8545M":  true,
	"HG8245A":  true,
	"HG8045H":  true,
	"EG8141A":  true,
	"HG8245C":  true,
	"HG8247H":  true,
	"HG8321R":  true,

	// ========== ZTE Single-Band ==========
	"F663N":     true,
	"F663NV3a":  true,
	"F663NV3A":  true,
	"F663NV9":   true,
	"F609":      true,
	"F609V1":    true,
	"F609 V1":   true,
	"F609V2":    true,
	"F609 V2":   true,
	"F609V5.2":  true,
	"F609 V5.2": true,
	"F609V5.3":  true,
	"F609 V5.3": true,
	"F660":      true,
	"F660V5":    true,
	"F660 V5":   true,
	"F660V6":    true,
	"F660 V6":   true,
	"F660V8":    true,
	"F660 V8":   true,
	"F623":      true,
	"F460":      true,
	"F460V5":    true,
	"F460 V5":   true,
	"F460V6":    true,
	"F460 V6":   true,
	"F450":      true,
	"F612W":     true,
	"F460E":     true,
	"F460EP":    true,
	"F420":      true,
	"F410":      true,
	"F477":      true,
	"F477V2":    true,

	// ========== Fiberhome Single-Band ==========
	"AN5506-04-FG": true,
	"AN550604FG":   true,
	"AN5506-04-F":  true,
	"AN550604F":    true,
	"AN5506-02-B":  true,
	"AN550602B":    true,
	"HG6243C":      true,
	"AN5506-02-F":  true,
	"AN550602F":    true,
	"AN5506-02-FG": true,
	"AN550602FG":   true,
	"AN5506-01-A":  true,
	"AN550601A":    true,
	"AN5506-01-F":  true,
	"AN550601F":    true,
	"AN5506-02-A":  true,
	"AN550602A":    true,

	// ========== VSOL Single-Band ==========
	"V2802GWT":  true,
	"HG323RGWT": true,
	"HG325N":    true,
	"HG322WT":   true,
	"HG322RGW":  true,
	"V2801RGW":  true,
	"V2802GW":   true,
	"HG323RGW":  true,
	"V2804N":    true,
	"V2804RGWT": true,
	"V2801WT":   true,
	"V2804N-Z":  true,
	"V2804NZ":   true,
	"V1600D":    true,
	"V1600G":    true,
	"V1600GS":   true,
	"V2801EW":   true,
	"V2801E":    true,
	"V1601E":    true,

	// ========== C-Data Single-Band ==========
	"FD512XW-R460": true,
	"FD512XWR460":  true,
	"FD504XW-R460": true,
	"FD504XWR460":  true,
	"FD514XW":      true,
	"FD612XW-R460": true,
	"FD612XWR460":  true,
	"FD712XW-R460": true,
	"FD712XWR460":  true,
	"FD511GW-G":    true,
	"FD511GWG":     true,
	"FD1101S":      true,
	"FD1104":       true,

	// ========== Zimmlink Single-Band ==========
	"ZL-2113X":    true,
	"ZL2113X":     true,
	"ZL-2113XV1":  true,
	"ZL2113XV1":   true,
	"ZL-2113X-V1": true,
	"ZL2113XV2":   true,
	"ZL-2113XV2":  true,
	"ZL-2113X-V2": true,
	"ML212X":      true,

	// ========== Nokia / Alcatel-Lucent Single-Band ==========
	"G-140W-F": true,
	"G140WF":   true,
	"I-240W-A": true,
	"I240WA":   true,
	"G-010G-P": true,
	"G010GP":   true,

	// ========== BDCOM Single-Band ==========
	"P1501C": true,
	"P1501D": true,
	"P1501E": true,
	"P1601C": true,
	"P1601D": true,

	// ========== Other / Misc Single-Band ==========
	"GP1704":   true,
	"GP1702":   true,
	"P1702":    true,
	"GN256":    true,
	"GN231":    true,
	"UF-WIFI":  true,
	"UFWIFI":   true,
	"HT803G-W": true,
	"HT803GW":  true,
	"RL821GW":  true,
	"HA7244":   true,
}

// Note: Unknown ONU models not listed above will be treated as single-band by default
// for safety. This ensures that devices without 5GHz support don't accidentally
// get configured with 5GHz WLAN settings.
