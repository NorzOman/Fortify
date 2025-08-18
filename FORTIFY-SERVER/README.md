# Fortify : Mobile Security Suite (v2.0)

## Overview

Neal will handle this task

He has been explained all the things he need to do

## Job Tracking Table Columns

| Column Name       | Description                                                                                                                                                                                                 |
| :---------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `job id`          | ID that will be generated and returned to the app client so it knows the job status.                                                                                                                        |
| `jwt_token`       | Stores the token from the first request. When the client polls for the job ID, the backend will only respond if the associated token is correct.                                                             |
| `input_file_path` | The full path where the APK or `message.txt` is stored (e.g., `/input/phishing` or `/input/malware`).                                                                                                     |
| `status`          | Defaults to `pending`. When the backend completes the task, it will override this to `completed`.                                                                                                          |
| `output_file_path`| Contains the path to the output report (e.g., `report.pdf`). The backend creates and overrides this PDF.                                                                                                   |
| `confidence`      | Confidence score added by the backend. Defaults to `null` until the task is completed.                                                                                                                     |
| `detection`       | Detection status added by the backend. Defaults to `null` until the task is completed.                                                                                                                     |

### Server Workflow

The server workflow involves taking requests from endpoints mentioned in the `Fortify-app` folder within this repository. It handles these routes by taking the request, creating a job ID, using the JWT token, and then allowing the backend to perform the task.

There may be some discrepancies between what is expected by the app and the current implementation, but this is acceptable for now. The team lead will handle integration later.
