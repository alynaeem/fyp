import glob
import os

files = glob.glob('news_collector/scripts/*.py')
modified_count = 0

for filepath in files:
    with open(filepath, 'r') as f:
        content = f.read()
        
    if 'self._store_processed(aid, processed)' in content:
        content = content.replace(
            'self._store_processed(aid, processed)',
            'nlp._RedisIO().write_processed(aid, processed)'
        )
        with open(filepath, 'w') as f:
            f.write(content)
        modified_count += 1
        print(f"Patched: {filepath}")

print(f"Total files patched: {modified_count}")
