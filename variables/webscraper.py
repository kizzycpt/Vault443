import requests

class WebScraper:
    
    
    #--- Response to URl request ----------
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


#instances
web_scraper = WebScraper()


if __name__ == "__main__":
    web_scraper.test_request()