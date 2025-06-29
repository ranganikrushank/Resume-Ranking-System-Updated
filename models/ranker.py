from sentence_transformers import SentenceTransformer, util
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
import re

model = SentenceTransformer("all-mpnet-base-v2")

def clean_text(text):
    text = re.sub(r"[^a-zA-Z0-9 ]", " ", text).lower()
    words = text.split()
    return [w for w in words if w not in ENGLISH_STOP_WORDS and len(w) > 2]

def rank_resume(resume_text, job_description):
    emb = model.encode([resume_text, job_description])
    cosine_sim = util.cos_sim(emb[0], emb[1]).item()

    resume_keywords = set(clean_text(resume_text))
    jd_keywords = set(clean_text(job_description))
    keyword_overlap = len(resume_keywords & jd_keywords) / max(len(jd_keywords), 1)

    final_score = (cosine_sim * 50) + (keyword_overlap * 50)
    return round(final_score, 2), round(cosine_sim, 2)