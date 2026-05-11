import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

class WebScraper:
    
    
    #--- Test Response to URl request ----------
    def test_request(self):
        try:
            #url must include full format e.g (https://www.google.com)
            url = input("Enter choice URL: ")
            search = "prices"
            
            response = requests.get(url)

            print(response.status_code)
            print(response.headers)
            print(response.text)

            if search in response.text:
                print("use beautiful soup to fetch RAW HTML data")
            else:
                print("[X] No data [X]\nUse playwright to render and move forward")


        except Exception as e:
            print("error {e}")

    
    def fetch_data(self):
        
        try: 
            #Enter domain use domain and root lvl. e.g. (google.com or cia.gov or temple.edu or something.org/page )
            domain = str(input("Enter Domain: "))
            url = f"https://www.{domain}"

            response = requests.get(url)

            print(response.status_code)
            print(response.headers)
            print(response.text)
        
        except Exception as e:
            print(f"Error when fetching data: {e}")
    

        search_flag = str(input("Insert Search Filter: "))


        #Find out what framework is needed
        if search_flag in response.text:
            soup = BeautifulSoup(response.text, "html.parser")
        
        else:
            try:
                with sync_playwright() as p:
                    
                    #browser windows will not pop up 
                    browser = p.chromium.launch(headless=True)

                    page = browser.new_page()
                    page.goto(url)

                    page.wait_for_selector(search_flag)

                html = page.content()
                soup = BeautifulSoup(html, "html.parser")

            except Exception as e:
                print(f"Error parsing data. {e}")



#instances
web_scraper = WebScraper()


if __name__ == "__main__":
    web_scraper.fetch_data()