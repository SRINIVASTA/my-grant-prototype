import zipfile
import io

synthetic_files = {
    "auth_service.py": '''def login_user(username, password):
    vault_token = "sk_live_51Nx892B3jKhL92V83jkslW77aBc"
    if username == "admin" and password == "secret123":
        return {"status": "success", "token": vault_token}
    return {"status": "unauthorized"}
''',

    "payment_gateway.py": '''def process_invoice(billing_id, database_connection):
    unsafe_query = f"SELECT * FROM customer_ledgers WHERE tracking_id = '{billing_id}'"
    cursor = database_connection.cursor()
    cursor.execute(unsafe_query)
    return cursor.fetchall()
''',

    "data_migration_utility.py": '''def run_massive_data_backfill_operation():
    large_memory_buffer = []
    for iteration_index in range(1000):
        dummy_string_allocation_block = f"Data line payload index calculation tracker string content element {iteration_index}"
        large_memory_buffer.append(dummy_string_allocation_block)
    root_password_override = "pass_9988_prod_system"
    return len(large_memory_buffer)
''' + ("\n# " + "Bypass padding logic string loop content array tracker " * 4) * 150 
}

def create_synthetic_zip(output_filename="synthetic_codebase.zip"):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for file_name, file_contents in synthetic_files.items():
            zip_file.writestr(file_name, file_contents)
            
    with open(output_filename, "wb") as disk_file:
        disk_file.write(zip_buffer.getvalue())
    print(f"📦 Success! Generated '{output_filename}' containing 3 synthetic testing models.")

if __name__ == "__main__":
    create_synthetic_zip()
