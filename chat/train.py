# train.py
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
import json
from env import RulepackEnv

# Load candidates (example JSONL or list)
with open("candidates.jsonl", "r", encoding="utf-8") as f:
    candidates = [json.loads(line) for line in f if line.strip()]

# minimal rulepack snapshot
rulepack = {}

env = RulepackEnv(candidates[:200], rulepack)  # use a subset
vec_env = DummyVecEnv([lambda: env])

model = PPO("MlpPolicy", vec_env, verbose=1, tensorboard_log="./tb_rl")
model.learn(total_timesteps=5000)
model.save("rulepack_agent")

# Save updated rulepack if desired
import json
with open("rulepack_after.json", "w", encoding="utf-8") as fh:
    json.dump(rulepack, fh, indent=2)
