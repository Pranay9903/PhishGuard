from app import create_app
from app.models import db, Analysis
import os
import time

try:
    from celery_app import celery_app
except Exception:
    celery_app = None


def capture_screenshot_sync(analysis_id, url):
    """Synchronous fallback when Celery/Redis is not available."""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
    except ImportError:
        return {'error': 'Selenium not available'}

    analysis = Analysis.query.get(analysis_id)
    if not analysis:
        return {'error': 'Analysis not found'}

    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--window-size=1920,1080')

    driver = None
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)

        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, 'body'))
        )

        time.sleep(2)

        screenshot_dir = 'uploads/screenshots'
        os.makedirs(screenshot_dir, exist_ok=True)

        screenshot_path = f'{screenshot_dir}/screenshot_{analysis_id}.png'
        driver.save_screenshot(screenshot_path)

        analysis.screenshot_path = screenshot_path
        db.session.commit()

        return {'screenshot_path': screenshot_path}

    except Exception as e:
        return {'error': str(e)}

    finally:
        if driver:
            driver.quit()


if celery_app:
    @celery_app.task
    def capture_screenshot(analysis_id, url):
        app = create_app()

        with app.app_context():
            analysis = Analysis.query.get(analysis_id)
            if not analysis:
                return {'error': 'Analysis not found'}

            try:
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options
                from selenium.webdriver.common.by import By
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
            except ImportError:
                return {'error': 'Selenium not available'}

            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')

            driver = None
            try:
                driver = webdriver.Chrome(options=chrome_options)
                driver.get(url)

                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, 'body'))
                )

                time.sleep(2)

                screenshot_dir = 'uploads/screenshots'
                os.makedirs(screenshot_dir, exist_ok=True)

                screenshot_path = f'{screenshot_dir}/screenshot_{analysis_id}.png'
                driver.save_screenshot(screenshot_path)

                analysis.screenshot_path = screenshot_path
                db.session.commit()

                return {'screenshot_path': screenshot_path}

            except Exception as e:
                return {'error': str(e)}

            finally:
                if driver:
                    driver.quit()