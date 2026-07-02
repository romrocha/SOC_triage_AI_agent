from sentence_transformers import SentenceTransformer
import numpy as np
from typing import List
from ..config import EMBEDDING_MODEL_NAME


class Embedder:
    def __init__(self, model_name: str = None):
        self.model_name = model_name or EMBEDDING_MODEL_NAME
        self.model = SentenceTransformer(self.model_name)

    def encode(self, texts: List[str]) -> List[List[float]]:
        arr = self.model.encode(texts, show_progress_bar=False)
        return [list(map(float, x)) for x in np.array(arr)]
