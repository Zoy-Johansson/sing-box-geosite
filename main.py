import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
import shutil
from io import StringIO

# 映射字典（已支持 PROCESS-NAME）
MAP_DICT = {'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
            'DOMAIN-KEYWORD':'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
            'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr',
            'IP6-CIDR': 'ip_cidr','SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
            'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex",
            'PROCESS-NAME': 'process_name'}

# ================== 适配 workflow 的清理逻辑 ==================
# 因为 workflow 会 cd 到 ./rule/ 再运行 python ../main.py
# 所以这里我们用 "." 表示当前目录（就是 rule 文件夹）
rule_dir = "."

if os.path.exists(rule_dir):
    for filename in os.listdir(rule_dir):
        file_path = os.path.join(rule_dir, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f"⚠️ 删除失败 {file_path}：{e}")
    print(f"✅ 已清空 rule 文件夹（当前目录）")
else:
    os.makedirs(rule_dir, exist_ok=True)
    print(f"✅ rule 文件夹已自动创建")
# ============================================================

def read_yaml_from_url(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    yaml_data = yaml.safe_load(response.text)
    return yaml_data

def read_list_from_url(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        csv_data = StringIO(response.text)
        df = pd.read_csv(csv_data, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'], on_bad_lines='skip')
    else:
        return None
    filtered_rows = []
    rules = []
    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {"type": "logical", "mode": "and", "rules": []}
            pattern = ",".join(row.values.astype(str))
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                for keyword in MAP_DICT.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({MAP_DICT[keyword]: value})
            rules.append(rule)
    for index, row in df.iterrows():
        if 'AND' not in row['pattern']:
            filtered_rows.append(row)
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    rules = []
    if link.endswith('.yaml') or link.endswith('.txt'):
        try:
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                line_content = lines[0]
                items = line_content.split()
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address[1:]
                            if address.startswith('.'):
                                address = address[1:]
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)
                if ',' in address:
                    address = address.split(',', 1)[0]
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        except:
            df, rules = read_list_from_url(link)
    else:
        df, rules = read_list_from_url(link)
    return df, rules

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def parse_list_file(link, output_directory):
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(parse_and_convert_to_dataframe, [link]))
            dfs = [df for df, rules in results]
            rules_list = [rules for df, rules in results]
            df = pd.concat(dfs, ignore_index=True)
        df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
        df = df.drop_duplicates().reset_index(drop=True)
        df['pattern'] = df['pattern'].replace(MAP_DICT)
        
        result_rules = {"version": 3, "rules": []}
        domain_entries = []
        for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
            if pattern == 'domain_suffix':
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
            elif pattern == 'domain':
                domain_entries.extend([address.strip() for address in addresses])
            else:
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
        
        domain_entries = list(set(domain_entries))
        if domain_entries:
            result_rules["rules"].insert(0, {'domain': domain_entries})

        file_name = os.path.join(output_directory, f"{os.path.basename(link).split('.')[0]}.json")
        with open(file_name, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')
            output_file.write(result_rules_str)
        
        srs_path = file_name.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
        return file_name
    except Exception as e:
        print(f'获取链接出错，已跳过：{link}，原因：{str(e)}')
        pass

# ====================== 主程序 ======================
with open("../links.txt", 'r') as links_file:   # ← 保持 ../ 因为 workflow 在 rule/ 目录运行
    links = links_file.read().splitlines()
links = [l for l in links if l.strip() and not l.strip().startswith("#")]

output_dir = "."   # ← 关键修复：输出到当前目录（就是 rule/）

result_file_names = []
for link in links:
    result_file_name = parse_list_file(link, output_directory=output_dir)
    result_file_names.append(result_file_name)

print(f"\n🎉 全部处理完成！共生成 {len(result_file_names)} 个规则集（已存入 rule 文件夹）")
