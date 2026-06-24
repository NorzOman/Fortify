# How to Run the Fortify Server part2

1. **Navigate to the backend folder**

```bash
cd backend_server
```

2. **Install dependencies**

* Minimal PyTorch install (CPU-only):

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

* Other required Python packages:

```bash
pip install flask requests transformers
```

3. **Run the server**

```bash
python3 server.py
```
4. **Test the server**

```bash
python3 test.py
```

> If the test runs successfully, your Fortify server is working!

5. **Troubleshooting**

* If you encounter any other issues, ask ChatGPT for help.

