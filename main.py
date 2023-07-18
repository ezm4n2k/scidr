import requests
import base64
from datetime import datetime
from dateutil.relativedelta import relativedelta
import shodan
import json 
import os

def load_config(filename):
    try:
        with open(filename, "r") as config_file:
            config = json.load(config_file)
            return config
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_config(filename, config):
    with open(filename, "w") as config_file:
        json.dump(config, config_file, indent=4)
        
def search_websites_on_cidr(cidr, api_key):
    try:
        api = shodan.Shodan(api_key)
        results = api.search(f"net:{cidr}")
        ip_port_list = [f"{result['ip_str']}:{result['port']}" for result in results['matches']]
        return ip_port_list
    except shodan.APIError as e:
        print(f"Error: {e}")
        return []

def search_hunterhow(ip, api_key):
    query = f'ip=="{ip}"'
    encoded_query = base64.urlsafe_b64encode(query.encode("utf-8")).decode('ascii')
    page = 1
    page_size = 100
    end_time = datetime.now().strftime('%Y-%m-%d')
    one_month_ago = datetime.now() - relativedelta(days=30)
    start_time = one_month_ago.strftime('%Y-%m-%d')
    url = "https://api.hunter.how/search?api-key=%s&query=%s&page=%d&page_size=%d&start_time=%s&end_time=%s" % (
        api_key, encoded_query, page, page_size, start_time, end_time
    )
    r = requests.get(url)
    data = r.json()['data']['list']
    ip_port_list = [f"{entry['ip']}:{entry['port']}" for entry in data]
    return ip_port_list

def remove_duplicates_from_file(filename):
    try:
        with open(filename, 'r') as file:
            lines = file.read().splitlines()
        unique_lines = set(lines)
        with open(filename, 'w') as file:
            file.write('\n'.join(unique_lines))
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        
if __name__ == "__main__":
    config_filename = 'config.json'
    config = load_config(config_filename)

    api_key_shodan = config.get('shodan_api_key')
    
    api_key_hunterhow = config.get('hunterhow_api_key')
    
    if api_key_shodan =="":
        api_key_shodan = input("Please enter your Shodan API key: ")
        config['shodan_api_key'] = api_key_shodan

    if api_key_hunterhow=="":
        api_key_hunterhow = input("Please enter your HunterHow API key: ")
        config['hunterhow_api_key'] = api_key_hunterhow
    save_config(config_filename, config)
    
    cidr_ip_range = input('Enter CIDR:')
    shodan_results = search_websites_on_cidr(cidr_ip_range, api_key_shodan)
    hunterhow_results = search_hunterhow(cidr_ip_range, api_key_hunterhow)
    combined_results = shodan_results + hunterhow_results
    with open('Result.txt', 'w') as file:
        file.write('\n'.join(combined_results))
    remove_duplicates_from_file('Result.txt')
    print("Result in Result.txt")
