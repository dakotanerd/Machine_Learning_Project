import json
from env import RulepackEnv
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rulepack", required=True)
    parser.add_argument("--candidates", required=False)
    parser.add_argument("--episodes", type=int, default=50)
    args = parser.parse_args()

    # Load rulepack
    with open(args.rulepack, "r", encoding="utf-8") as f:
        rulepack = json.load(f)

    # Load candidates
    candidates_path = args.candidates or "candidates.jsonl"
    candidates = []
    with open(candidates_path, "r", encoding="utf-8") as f:
        for line in f:
            candidates.append(json.loads(line))

    # Create RL environment
    env = RulepackEnv(candidates, rulepack)

    # now you can continue with episodes/training
    for ep in range(args.episodes):
        obs = env.reset()
        done = False
        total_reward = 0
        while not done:
            action = env.action_space.sample()  # replace with your RL policy
            obs, reward, done, info = env.step(action)
            total_reward += reward
        print(f"Episode {ep+1}: reward={total_reward}, final_score={info.get('final_score')}")

if __name__ == "__main__":
    main()
