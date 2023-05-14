import requests
from bs4 import BeautifulSoup


def create_file(file_name: str) -> None:
    headers = {
        "Accept": "*/*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
    }
    list_joke = []
    for num_page in range(1, 5):
        url = f"https://anekdotbar.ru/pro-shtirlica/page/{num_page}/"
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.content, 'html.parser')
        for joke in soup.find_all("div", class_='tecst'):
            text_to_append = joke.text.split("\n")[1]
            list_joke.append(f"{text_to_append}\n")
    with open(file_name, 'w', encoding="UTF-8") as file:
        for elem in list_joke:
            file.write(elem)
