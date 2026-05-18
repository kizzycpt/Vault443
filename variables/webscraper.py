
import requests, time

from bs4                    import BeautifulSoup
from playwright.sync_api    import sync_playwright, Page
from pathlib                import Path
from datetime               import datetime


base_dir = Path(__file__).resolve().parent


class WebScraper:
        
    def fetch_data(self):
        
        try:
            try: 
                #Enter domain use domain and root lvl. e.g. (google.com or cia.gov or temple.edu or something.org/page )
                domain = str(input("Enter Domain: "))
                url = f"https://www.{domain}"

                time_stamp = datetime.now().strftime("%Y_%B_%d_%H_%M%p")
                log_path = base_dir / "peels" / f"{domain}" / f"{time_stamp}.json"
                log_path.parent.mkdir(parents=True, exist_ok=True)
                


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

                with open(log_path, "a") as f:
                    f.write(soup.prettify())

                print(soup.prettify())
                log_path.write_text(soup.prettify())
                
                result = soup.find(string=search_flag)

                print(result)
            

        
            else:
                try:
                    with sync_playwright() as p:
                        
                        #browser windows will not pop up 
                        browser = p.chromium.launch(headless=True)

                        page = browser.new_page()
                        page.goto(url)


                        html = page.content()
                        soup = BeautifulSoup(html, "html.parser")
                        
                        with open(log_path, "a") as f:
                            f.write(soup.prettify())
                        
                        print(soup.prettify())
                        log_path.write_text(soup.prettify())

                        result = soup.find(string=search_flag)

                        print(result)
            

                except Exception as e:
                    print(f"Error parsing data. {e}")

        except Exception as e:
            print(f"Error Scraping Domain. {e}")


#instances
web_scraper = WebScraper()


if __name__ == "__main__":
    web_scraper.fetch_data()