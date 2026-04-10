from playwright.sync_api import sync_playwright

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        print("Navigating to https://www.ransomware.live/...")
        page.goto("https://www.ransomware.live/", timeout=60000)
        page.wait_for_load_state("networkidle")
        
        print(f"Page Title: {page.title()}")
        
        # Check for the expected anchors
        selector = 'a.text-body-emphasis.text-decoration-none'
        anchors = page.query_selector_all(selector)
        print(f"Found {len(anchors)} anchors with selector '{selector}'")
        
        if len(anchors) == 0:
            print("Trying generic 'a' search inside cards...")
            # Look for common victim card patterns
            cards = page.query_selector_all('div.card')
            print(f"Found {len(cards)} cards")
            for i, card in enumerate(cards[:5]):
                print(f"Card {i} HTML: {card.inner_html()[:200]}...")
                link = card.query_selector('a')
                if link:
                    print(f"  Link: {link.get_attribute('href')}")
        
        browser.close()

if __name__ == "__main__":
    main()
