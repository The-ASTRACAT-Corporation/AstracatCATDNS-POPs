
from playwright.sync_api import sync_playwright

def run(playwright):
    browser = playwright.chromium.launch()
    page = browser.new_page()

    # Handle the alert dialog
    page.on("dialog", lambda dialog: dialog.accept())

    page.goto("http://astracat:astracat@localhost:8080")

    # Import the zone file
    with page.expect_file_chooser() as fc_info:
        page.click('button:has-text("Import BIND9 Zone File")')
    file_chooser = fc_info.value
    file_chooser.set_files('example.com.zone')

    # Wait for the zone to be imported and the page to reload
    page.wait_for_selector('text=example.com.')

    # Click the manage button for the example.com. zone
    page.click('button:has-text("Manage")')

    page.screenshot(path="jules-scratch/verification/records_before_edit.png")

    # Edit the record
    page.click('button:has-text("Edit")')
    page.fill('input[name="record-value"]', '5.6.7.8')
    page.click('button:has-text("Save")')

    page.screenshot(path="jules-scratch/verification/records_after_edit.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
