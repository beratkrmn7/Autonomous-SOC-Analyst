import os, glob, re

for p in glob.glob('tests/**/*.py', recursive=True):
    with open(p, 'r') as f:
        content = f.read()
    
    new_content = re.sub(r'\"source_line\"\s*:\s*\{.*?\}', '\"source_line\": None', content)
    
    if content != new_content:
        with open(p, 'w') as f:
            f.write(new_content)
        print(f'Fixed json source_line in {p}')
