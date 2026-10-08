import json, os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv('mad-ps-explanation-service/.env')
key = os.environ.get('GEMINI_API_KEY', '').strip().strip('\'"<>')

for path_str in ['mad-ps-explanation-service/data/llm_config.json', 'data/llm_config.json']:
    p = Path(path_str)
    if p.exists():
        with open(p, 'r') as f:
            cfg = json.load(f)
        cfg['api_key'] = key
        cfg['provider'] = 'gemini'
        cfg['model_name'] = 'gemini-3.6-flash'
        for panelist in cfg.get('panelists', []):
            if panelist.get('provider') == 'gemini':
                panelist['api_key'] = key
                panelist['model_name'] = 'gemini-3.6-flash'
        if cfg.get('judge', {}).get('provider') == 'gemini':
            cfg['judge']['api_key'] = key
            cfg['judge']['model_name'] = 'gemini-3.1-pro-preview'
        with open(p, 'w') as f:
            json.dump(cfg, f, indent=2)
        print(f'Synced {p} with key length {len(key)}')
