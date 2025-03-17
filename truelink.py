import requests
import argparse
import os

def get_api_key(api_key_path):
  if not os.path.exists(api_key_path):
    raise FileNotFoundError(f"The API key file was not found: {api_key_path}")
  with open(api_key_path, 'r') as f:
    return f.read().strip()

def analyze_url(short_url, show_engine_results, api_key):
  try:
    # Faz a request para pegar a URL original
    response = requests.get(short_url, allow_redirects=True)
    original_url = response.url
    
    # Monta a request para a API do VirusTotal
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {
      "accept": "application/json",
      "x-apikey": api_key
    }
    payload = {"url": original_url}
    
    # Faz a request para a API do VirusTotal
    response = requests.post(url, data=payload, headers=headers)

    data = response.json()
    
    # Se a resposta tiver algum erro da API, exibe e retorna
    if "error" in data:
      print(f"Error from VirusTotal API: {data['error']['message']}")
      return

    analysis_id = data["data"]["id"]
    url_analysis = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(url_analysis, headers=headers)
    response.raise_for_status()  # Verifica novamente se a resposta é bem-sucedida
    data = response.json()
    
    stats = data['data']['attributes']['stats']
    results = data['data']['attributes']['results']

    malicious = stats['malicious']
    suspicious = stats['suspicious']
    undetected = stats['undetected']
    harmless = stats['harmless']

    # Exibe resultados
    print(f"Security analysis for the URL: {short_url}")
    print(f"Original URL: {original_url}\n")
    print("Analysis statistics:")
    print(f"  - Malicious URL: {malicious} engines")
    print(f"  - Suspicious URL: {suspicious} engines")
    print(f"  - Undetected URL: {undetected} engines")
    print(f"  - Harmless URL: {harmless} engines")

    if show_engine_results:
      print("Engine verification results:")
      for engine, data in results.items():
        print(f"  - {data['engine_name']}: {data['result']} (Method: {data['method']})")

  except requests.exceptions.HTTPError as errh:
    print(f"HTTP error occurred: {errh}")
  except requests.exceptions.RequestException as err:
    print(f"Error during the request: {err}")
  except KeyError as e:
    print(f"Unexpected data format: {e}")
  except Exception as e:
    print(f"An error occurred: {e}")

def main():
  parser = argparse.ArgumentParser(description="Analyze the security of a shortened URL using VirusTotal")
  
  parser.add_argument("short_url", type=str, help="The shortened URL to analyze")
  parser.add_argument("--show-engines", action="store_true", help="Show the results for each security engine")
  parser.add_argument("--api-key-path", type=str, required=True, help="Path to the file containing the VirusTotal API key")

  args = parser.parse_args()

  try:
    api_key = get_api_key(args.api_key_path)
    analyze_url(args.short_url, args.show_engines, api_key)
  except FileNotFoundError as e:
    print(f"Error: {e}")

if __name__ == "__main__":
  main()
