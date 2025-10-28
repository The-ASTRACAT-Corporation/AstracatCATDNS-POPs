
from playwright.sync_api import sync_playwright

def run(playwright):
    browser = playwright.chromium.launch()
    page = browser.new_page()
    page.goto("http://astracat:astracat@localhost:8080")

    # Import the zone file
    with page.expect_file_chooser() as fc_info:
        page.click('button:has-text("Import BIND9 Zone File")')
    file_chooser = fc_info.value
    file_chooser.set_files('example.com.zone')

    # Wait for the zone to be imported
    page.wait_for_selector('text=example.com.')

    # Click the manage button for the example.com. zone
    page.click('button:has-text("Manage")')

    page.screenshot(path="jules-scratch/verification/records_page.png")

    # Add a new record
    page.click('button:has-text("Add Record")')
    page.fill('input[name="record-name"]', 'new')
    page.select_option('select[name="record-type"]', 'A')
    page.fill('input[name="record-ttl"]', '3600')
    page.fill('input[name="record-value"]', '1.2.3.4')
    page.click('button:has-text("Save")')

    page.screenshot(path="jules-scratch/verification/record_added.png")

    # Edit the record
    page.click('button:has-text("Edit")')
    page.fill('input[name="record-value"]', '5.6.7.8')
    page.click('button:has-text("Save")')

    page.screenshot(path="jules-scratch/verification/record_edited.png")

    # Delete the record
    page.click('button:has-text("Delete")')
    page.click('button:has-text("OK")')

    page.screenshot(path="jules-scratch/verification/record_deleted.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
