INDO_SCAM_KEYWORDS = {
    "bank": {
        "words": ["bri", "bca", "mandiri", "btn", "bni", "cimb", "danamon", "permata", "maybank", "panin", "ocbc", "hsbc", "muamalat", "syariah", "bsi", "jenius", "blu", "digibank"],
        "risk": "high",
        "label": "Banking phishing"
    },
    "logistik": {
        "words": ["jne", "jnt", "sicepat", "ninja", "anteraja", "indah", "cargo", "wahana", "pos", "tiki", "lion", "parcel", "paket", "dhl", "fedex"],
        "risk": "high",
        "label": "Paket/logistik palsu"
    },
    "pemerintah": {
        "words": ["bpjs", "jkn", "kemenkes", "kemendikbud", "djp", "pajak", "samsat", "ktp", "disdukcapil", "bansos", "pkh", "sembako"],
        "risk": "high",
        "label": "Instansi pemerintah palsu"
    },
    "fintech": {
        "words": ["pinjol", "pinjam", "kredit", "dana", "gopay", "ovo", "shopeepay", "spay", "linkaja", "isaku", "paylater", "akulaku", "kredivo", "indodana", "adapundi"],
        "risk": "high",
        "label": "Fintech/pinjol palsu"
    },
    "undian": {
        "words": ["hadiah", "undian", "menang", "pemenang", "doorprize", "giveaway", "kupon", "poin", "reward", "cashback"],
        "risk": "medium",
        "label": "Undian/hadiah palsu"
    },
    "ecommerce": {
        "words": ["tokopedia", "shopee", "lazada", "bukalapak", "blibli", "zalora", "jdid", "social", "market", "olx"],
        "risk": "medium",
        "label": "E-commerce palsu"
    },
    "telekom": {
        "words": ["telkom", "telkomsel", "indosat", "xl", "tri", "three", "axis", "smart", "byu", "im3"],
        "risk": "medium",
        "label": "Provider telekomunikasi palsu"
    },
    "tunai": {
        "words": ["saldo", "pulsa", "kuota", "topup", "top up", "transfer", "dana", "tarik", "tunai", "uang", "cash"],
        "risk": "medium",
        "label": "Penawaran saldo/pulsa palsu"
    }
}

SUSPICIOUS_TLDS = {
    "high": ["tk", "ml", "ga", "cf", "gq"],
    "medium": ["xyz", "top", "club", "online", "site", "live", "click", "link", "work", "bid", "loan", "men", "win", "review", "trade", "webcam", "rest"]
}

SUSPICIOUS_KEYWORDS_DOMAIN = [
    "secure", "login", "verify", "update", "confirm", "account",
    "claim", "bonus", "free", "promo", "flashsale", "diskon",
    "verifikasi", "konfirmasi", "aktifkan", "daftar"
]
