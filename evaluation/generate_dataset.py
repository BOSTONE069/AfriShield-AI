#!/usr/bin/env python3
"""Generate AfriShield's deterministic, anonymized multilingual benchmark."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DATASET_VERSION = "1.0.0"
DEFAULT_SIZE = 600
THREAT_TYPES = (
    "PHISHING",
    "SCAM",
    "MALWARE",
    "BUSINESS_EMAIL_COMPROMISE",
    "MISINFORMATION",
    "BENIGN",
)
LANGUAGES = {
    "en": {"name": "English", "locale": "Kenya"},
    "sw": {"name": "Swahili", "locale": "Kenya"},
    "sheng": {"name": "Sheng", "locale": "Kenya"},
    "fr": {"name": "French", "locale": "Senegal"},
    "ar": {"name": "Arabic", "locale": "Egypt"},
    "am": {"name": "Amharic", "locale": "Ethiopia"},
    "ha": {"name": "Hausa", "locale": "Nigeria"},
    "pt": {"name": "Portuguese", "locale": "Mozambique"},
}

SCENARIOS = {
    "PHISHING": ("mpesa", "kra", "university", "delivery"),
    "SCAM": ("job", "loan", "ngo", "sacco", "sim_swap", "mpesa"),
    "MALWARE": ("invoice", "delivery", "university"),
    "BUSINESS_EMAIL_COMPROMISE": ("sacco", "ngo", "invoice", "supplier"),
    "MISINFORMATION": ("public_health", "election", "mobile_network"),
    "BENIGN": ("mpesa", "kra", "university", "delivery", "job", "loan", "ngo", "sacco", "account", "payment"),
}

SCENARIO_VALUES = {
    "mpesa": ("M-Pesa", "https://mpesa-security.invalid/verify", "KES 8,500"),
    "kra": ("KRA iTax", "https://kra-refund.invalid/login", "KES 12,400"),
    "university": ("Student Portal", "https://student-portal.invalid/account", "KES 24,000"),
    "delivery": ("Parcel Service", "https://parcel-release.invalid/payment", "KES 350"),
    "job": ("Recruitment Office", "https://jobs-onboarding.invalid/form", "KES 2,000"),
    "loan": ("Mobile Loan", "https://instant-loan.invalid/apply", "KES 50,000"),
    "ngo": ("Community Aid NGO", "https://aid-grant.invalid/register", "KES 5,000"),
    "sacco": ("Umoja SACCO", "https://sacco-update.invalid/confirm", "KES 75,000"),
    "sim_swap": ("Mobile Network", "https://sim-restore.invalid/identity", "KES 1,000"),
    "invoice": ("Regional Supplier", "https://invoice-view.invalid/document", "KES 180,000"),
    "supplier": ("Approved Supplier", "https://supplier-record.invalid/update", "KES 240,000"),
    "public_health": ("Public Health Office", "https://health-alert.invalid/news", "KES 0"),
    "election": ("Election Desk", "https://election-update.invalid/breaking", "KES 0"),
    "mobile_network": ("Mobile Network", "https://network-notice.invalid/share", "KES 0"),
    "account": ("Customer Account Team", "https://example.org/account-help", "KES 0"),
    "payment": ("Finance Department", "https://example.org/payment-policy", "KES 16,000"),
}

TEMPLATES = {
    "en": {
        "PHISHING": "URGENT: {brand} account access expires {date}. Verify your login now at {url}.",
        "SCAM": "Congratulations. {brand} approved {amount} for you. Pay a processing fee today to claim it at {url}.",
        "MALWARE": "Open the attached {attachment} from {brand} and enable content immediately to view the document.",
        "BUSINESS_EMAIL_COMPROMISE": "CEO request: finance team, send a wire transfer of {amount} to the new supplier account today. Do not call; I am in a meeting.",
        "MISINFORMATION": "BREAKING: {brand} is hiding this secret warning. Forward to everyone before it is deleted.",
        "BENIGN": "Reminder from {brand}: the scheduled {scenario} meeting is on {date}. Verify the agenda with your usual contact; no payment or password is required.",
    },
    "sw": {
        "PHISHING": "HARAKA: Akaunti yako ya {brand} itafungwa {date}. Thibitisha nenosiri lako sasa kupitia {url}.",
        "SCAM": "Hongera, {brand} imekuidhinishia {amount}. Tuma ada ya usindikaji leo ili upokee pesa kupitia {url}.",
        "MALWARE": "Fungua kiambatisho {attachment} kutoka {brand} na uwashe yaliyomo mara moja kuona hati.",
        "BUSINESS_EMAIL_COMPROMISE": "Ombi la CEO: timu ya fedha itume {amount} kwa akaunti mpya ya msambazaji leo. Usipige simu, niko mkutanoni.",
        "MISINFORMATION": "HABARI MPYA: {brand} inaficha onyo hili la siri. Sambaza kwa kila mtu kabla halijafutwa.",
        "BENIGN": "Kumbusho kutoka {brand}: mkutano wa {scenario} ni {date}. Thibitisha ajenda kwa mawasiliano ya kawaida; hakuna malipo au nenosiri linalohitajika.",
    },
    "sheng": {
        "PHISHING": "Manze ni urgent: account ya {brand} itablockiwa {date}. Verify PIN yako hapa {url} sai.",
        "SCAM": "Umeshinda {amount} kutoka {brand}. Tuma processing fee leo ndio cash iingie, details {url}.",
        "MALWARE": "Fungua attachment {attachment} ya {brand}, then enable content ndio uone file yote.",
        "BUSINESS_EMAIL_COMPROMISE": "CEO amesema finance itume {amount} kwa supplier account mpya leo. Msipige simu juu niko meeting.",
        "MISINFORMATION": "Breaking maze: {brand} wanaficha hii story. Forward kwa kila mtu kabla wadelete.",
        "BENIGN": "Reminder ya {brand}: meeting ya {scenario} ni {date}. Verify agenda na contact yako kawaida; hakuna payment ama PIN inahitajika.",
    },
    "fr": {
        "PHISHING": "URGENT : votre compte {brand} expire le {date}. Vérifiez votre mot de passe maintenant sur {url}.",
        "SCAM": "Félicitations, {brand} vous accorde {amount}. Payez les frais de dossier aujourd'hui via {url}.",
        "MALWARE": "Ouvrez la pièce jointe {attachment} de {brand} et activez le contenu immédiatement.",
        "BUSINESS_EMAIL_COMPROMISE": "Demande du PDG : finance, virez {amount} vers le nouveau compte fournisseur aujourd'hui. Ne téléphonez pas, je suis en réunion.",
        "MISINFORMATION": "ALERTE : {brand} cache cet avertissement secret. Transférez-le à tout le monde avant sa suppression.",
        "BENIGN": "Rappel de {brand} : la réunion {scenario} est prévue le {date}. Vérifiez l'ordre du jour par le contact habituel; aucun paiement ni mot de passe n'est demandé.",
    },
    "ar": {
        "PHISHING": "عاجل: سينتهي حساب {brand} في {date}. تحقق من كلمة المرور الآن عبر {url}.",
        "SCAM": "تهانينا، وافقت {brand} على مبلغ {amount} لك. ادفع رسوم المعالجة اليوم عبر {url}.",
        "MALWARE": "افتح المرفق {attachment} من {brand} وفعّل المحتوى فوراً لعرض المستند.",
        "BUSINESS_EMAIL_COMPROMISE": "طلب المدير التنفيذي: حوّل قسم المالية {amount} إلى حساب المورد الجديد اليوم. لا تتصل، أنا في اجتماع.",
        "MISINFORMATION": "خبر عاجل: تخفي {brand} هذا التحذير السري. أرسله للجميع قبل حذفه.",
        "BENIGN": "تذكير من {brand}: اجتماع {scenario} مقرر في {date}. تحقق من جدول الأعمال عبر جهة الاتصال المعتادة؛ لا يلزم دفع أو كلمة مرور.",
    },
    "am": {
        "PHISHING": "አስቸኳይ፦ የ{brand} መለያዎ {date} ይዘጋል። የይለፍ ቃልዎን አሁን በ{url} ያረጋግጡ።",
        "SCAM": "እንኳን ደስ አለዎት፣ {brand} {amount} ፈቅዷል። ለመቀበል ዛሬ የሂደት ክፍያ በ{url} ይክፈሉ።",
        "MALWARE": "ከ{brand} የመጣውን {attachment} አባሪ ይክፈቱና ይዘቱን ወዲያውኑ ያንቁ።",
        "BUSINESS_EMAIL_COMPROMISE": "የዋና ሥራ አስፈጻሚ ጥያቄ፦ ፋይናንስ {amount} ዛሬ ወደ አዲሱ አቅራቢ ሂሳብ ያስተላልፍ። ስብሰባ ላይ ነኝ፣ አትደውሉ።",
        "MISINFORMATION": "ሰበር ዜና፦ {brand} ይህን ሚስጥራዊ ማስጠንቀቂያ እየደበቀ ነው። ከመጥፋቱ በፊት ለሁሉም ያጋሩ።",
        "BENIGN": "ከ{brand} ማስታወሻ፦ የ{scenario} ስብሰባ {date} ነው። አጀንዳውን በመደበኛ አድራሻ ያረጋግጡ፤ ክፍያ ወይም የይለፍ ቃል አያስፈልግም።",
    },
    "ha": {
        "PHISHING": "GAJAWA: Asusun {brand} zai rufe a {date}. Tabbatar da kalmar sirri yanzu a {url}.",
        "SCAM": "Taya murna, {brand} ta amince da {amount}. Biya kuɗin aiki yau ta {url} don karɓa.",
        "MALWARE": "Buɗe haɗe-haɗen {attachment} daga {brand}, sannan kunna abun ciki nan take.",
        "BUSINESS_EMAIL_COMPROMISE": "Buƙatar shugaban kamfani: kuɗi su aika {amount} zuwa sabon asusun mai kaya yau. Kada ku kira, ina taro.",
        "MISINFORMATION": "LABARI MAI ƊUMI: {brand} tana ɓoye wannan gargaɗin sirri. Tura wa kowa kafin a goge shi.",
        "BENIGN": "Tunatarwa daga {brand}: taron {scenario} zai kasance {date}. Tabbatar da jadawalin ta hanyar lambar da kuka saba; ba a buƙatar kuɗi ko kalmar sirri.",
    },
    "pt": {
        "PHISHING": "URGENTE: a conta {brand} expira em {date}. Confirme a palavra-passe agora em {url}.",
        "SCAM": "Parabéns, {brand} aprovou {amount}. Pague hoje a taxa de processamento através de {url}.",
        "MALWARE": "Abra o anexo {attachment} de {brand} e ative o conteúdo imediatamente para ver o documento.",
        "BUSINESS_EMAIL_COMPROMISE": "Pedido do diretor: finanças, transfiram {amount} para a nova conta do fornecedor hoje. Não telefonem, estou numa reunião.",
        "MISINFORMATION": "ÚLTIMA HORA: {brand} esconde este aviso secreto. Encaminhe para todos antes que seja apagado.",
        "BENIGN": "Lembrete de {brand}: a reunião sobre {scenario} será em {date}. Confirme a agenda pelo contacto habitual; não é exigido pagamento nem palavra-passe.",
    },
}

ATTACHMENTS = ("invoice.pdf.exe", "delivery-note.scr", "results.docm", "payment-advice.zip")
DATES = ("Monday", "Tuesday", "15 August", "before 17:00")
URL_PATTERN = re.compile(r"https?://[^\s]+")
SAFE_HOSTS = {"example.org"}


def generate_examples(size: int = DEFAULT_SIZE) -> list[dict[str, Any]]:
    """Return a balanced, deterministic set of synthetic benchmark records."""
    if not 300 <= size <= 1000:
        raise ValueError("Dataset size must be between 300 and 1000 examples.")

    base_per_cell = size // (len(LANGUAGES) * len(THREAT_TYPES))
    examples: list[dict[str, Any]] = []
    sequence = 1
    for language, language_meta in LANGUAGES.items():
        for threat_type in THREAT_TYPES:
            for variant in range(base_per_cell):
                scenario = SCENARIOS[threat_type][variant % len(SCENARIOS[threat_type])]
                brand, url, amount = SCENARIO_VALUES[scenario]
                text = TEMPLATES[language][threat_type].format(
                    brand=brand,
                    url=url,
                    amount=amount,
                    attachment=ATTACHMENTS[variant % len(ATTACHMENTS)],
                    date=DATES[variant % len(DATES)],
                    scenario=scenario.replace("_", " "),
                )
                text = f"{text} [Ref AFS-{sequence:04d}]"
                examples.append(_record(sequence, text, threat_type, language, language_meta, scenario, variant))
                sequence += 1

    # Fill the remainder with difficult benign cases so words such as account,
    # payment, and verify are not treated as malicious without supporting cues.
    while len(examples) < size:
        language = tuple(LANGUAGES)[len(examples) % len(LANGUAGES)]
        language_meta = LANGUAGES[language]
        scenario = ("account", "payment", "kra", "mpesa")[len(examples) % 4]
        brand, _, _ = SCENARIO_VALUES[scenario]
        text = TEMPLATES[language]["BENIGN"].format(
            brand=brand,
            scenario=scenario,
            date=DATES[len(examples) % len(DATES)],
            url="https://example.org/help",
            amount="KES 0",
            attachment="agenda.pdf",
        )
        text = f"{text} [Ref AFS-{sequence:04d}]"
        examples.append(_record(sequence, text, "BENIGN", language, language_meta, scenario, sequence))
        sequence += 1

    validate_examples(examples)
    return examples


def _record(
    sequence: int,
    text: str,
    threat_type: str,
    language: str,
    language_meta: dict[str, str],
    scenario: str,
    variant: int,
) -> dict[str, Any]:
    input_types = {
        "PHISHING": ("sms", "email", "social_message"),
        "SCAM": ("sms", "social_message", "email"),
        "MALWARE": ("email",),
        "BUSINESS_EMAIL_COMPROMISE": ("email",),
        "MISINFORMATION": ("social_message", "text"),
        "BENIGN": ("email", "sms", "text"),
    }
    return {
        "id": f"AFS-EVAL-{sequence:04d}",
        "dataset_version": DATASET_VERSION,
        "text": text,
        "input_type": input_types[threat_type][variant % len(input_types[threat_type])],
        "language": language,
        "language_name": language_meta["name"],
        "locale": language_meta["locale"],
        "threat_type": threat_type,
        "scenario": scenario,
        "is_malicious": threat_type != "BENIGN",
        "source": "synthetic_template",
        "review_status": "synthetic_unreviewed",
        "contains_personal_data": False,
    }


def validate_examples(examples: list[dict[str, Any]]) -> None:
    """Enforce benchmark size, balance, uniqueness, and anonymization rules."""
    if not 300 <= len(examples) <= 1000:
        raise ValueError("Evaluation dataset must contain 300-1000 records.")
    if len({example["id"] for example in examples}) != len(examples):
        raise ValueError("Evaluation IDs must be unique.")
    if len({example["text"] for example in examples}) != len(examples):
        raise ValueError("Evaluation messages must be unique.")
    if set(Counter(example["language"] for example in examples)) != set(LANGUAGES):
        raise ValueError("Every target language must be represented.")
    if set(Counter(example["threat_type"] for example in examples)) != set(THREAT_TYPES):
        raise ValueError("Every target threat type must be represented.")
    for example in examples:
        if example["source"] != "synthetic_template" or example["contains_personal_data"]:
            raise ValueError("Generated records must remain synthetic and anonymized.")
        for raw_url in URL_PATTERN.findall(example["text"]):
            hostname = (urlparse(raw_url.rstrip(".,;)")).hostname or "").lower()
            if not (hostname.endswith(".invalid") or hostname in SAFE_HOSTS):
                raise ValueError(f"Generated record contains a non-reserved hostname: {hostname}")


def write_jsonl(examples: list[dict[str, Any]], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        for example in examples:
            handle.write(json.dumps(example, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE)
    parser.add_argument("--output", type=Path, default=Path("evaluation/data/afrishield_eval_v1.jsonl"))
    args = parser.parse_args()
    examples = generate_examples(args.size)
    write_jsonl(examples, args.output)
    print(f"Wrote {len(examples)} validated examples to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
