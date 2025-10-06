import gymnasium
from gymnasium import spaces
import numpy as np
from typing import List, Dict

# Placeholder: implement real evaluation
def evaluate_rulepack(rulepack) -> float:
    return np.random.rand()

class RulepackEnv(gymnasium.Env):
    """
    Observation: numeric vector describing one candidate.
    Action: discrete {reject, accept_add, incr_score, defer}
    """
    metadata = {"render_modes": ["human"]}

    def __init__(self, candidates: List[Dict], rulepack: Dict):
        super().__init__()
        self.candidates = candidates
        self.rulepack = rulepack
        self.idx = 0
        # Example observation size: [severity_num, freq, score, context_len, lang_onehot...]
        self.observation_space = spaces.Box(low=-1e6, high=1e6, shape=(8,), dtype=np.float32)
        self.action_space = spaces.Discrete(4)
        self.base_score = evaluate_rulepack(rulepack)
        self._rng = np.random.default_rng()

    def _make_obs(self, cand):
        sev_map = {"Critical":3, "High":2, "Medium":1, "Low":0, None:0}
        sev = sev_map.get(cand.get("severity"), 0)
        freq = float(cand.get("frequency", 1))
        score = float(cand.get("rule_score", 0.0))
        lang = cand.get("lang", "py")
        lang_onehot = [1.0 if lang.startswith(x) else 0.0 for x in ("py","js","java")]
        vec = np.array([sev, freq, score, len(cand.get("example_context",""))] + lang_onehot, dtype=np.float32)
        if vec.shape[0] < self.observation_space.shape[0]:
            vec = np.pad(vec, (0, self.observation_space.shape[0]-vec.shape[0]))
        return vec

    def reset(self, *, seed=None, options=None):
        # Gymnasium expects seed as keyword-only argument
        super().reset(seed=seed)  # sets self.np_random
        if seed is not None:
            self._rng = np.random.default_rng(seed)
        self.idx = 0
        self.base_score = evaluate_rulepack(self.rulepack)
        obs = self._make_obs(self.candidates[self.idx])
        info = {"final_score": self.base_score}
        return obs, info

    def step(self, action):
        cand = self.candidates[self.idx]
        # Apply action to rulepack
        if action == 1:  # accept_add
            patt = cand["candidate_pattern"]
            ext = ".generic"
            rules = self.rulepack.setdefault(ext, [])
            rules.append({"pattern": patt, "description": cand.get("example_context",""), "reward_score": 1.0})
        elif action == 2:  # incr_score
            ext = ".generic"
            for r in self.rulepack.get(ext, []):
                if r.get("pattern") == cand["candidate_pattern"]:
                    r["reward_score"] = r.get("reward_score", 1.0) + 1.0
                    break

        self.idx += 1
        done = (self.idx >= len(self.candidates))
        obs = self._make_obs(self.candidates[self.idx-1]) if not done else np.zeros(self.observation_space.shape)
        reward = 0.0
        info = {}

        if done:
            new_score = evaluate_rulepack(self.rulepack)
            reward = float(new_score - self.base_score)
            info["final_score"] = new_score

        return obs, reward, done, info

    def render(self, mode="human"):
        print(f"Index {self.idx}, Current Rulepack: {self.rulepack}")
