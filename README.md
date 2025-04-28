# IAM Change Notifier

---
This repository contains the implementation for the Capstone project in the Cloud Security course (95-746) at Carnegie 
Mellon University. The project contains a Serverless pipeline that watches IAM policy write-events and sends a Slack 
alert with a unified JSON diff seconds after the change.

---

## Project Structure
More detailed information on each file and its structure is provided in the resepective script through comments.

```
src/
 ├─ config.py          # env-var & constant helpers
 ├─ notifier.py        # Lambda handler (main logic)
 └─ policy_event.py    # event-parsing & ARN helpers
requirements.txt       # pinned third-party libs
.gitignore
README.md
```

---

## Usage & Deployment

1. Clone repository: `git clone https://github.com/tcw0/cloud-sec.git`
2. Install dependencies into `build/` folder: `pip install -r requirements.txt -t build/`
3. Copy app code into `build/` folder: `cp -r src build/`
4. Create deployment package: `cd build && zip -r ../function.zip .`
5. Upload `function.zip` in the Lambda console

