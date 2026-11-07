
import os
import boto3

SENDER_EMAIL = os.getenv(
    "SES_FROM_EMAIL",
    "ktcloudsecu404@gmail.com"
)

AWS_REGION = "ap-northeast-2"


def send_email(to_email, subject, body):
    ses = boto3.client("ses", region_name=AWS_REGION)

    response = ses.send_email(
        Source=SENDER_EMAIL,
        Destination={
            "ToAddresses": [to_email]
        },
        Message={
            "Subject": {
                "Data": subject,
                "Charset": "UTF-8"
            },
            "Body": {
                "Text": {
                    "Data": body,
                    "Charset": "UTF-8"
                }
            }
        }
    )

    return response["MessageId"]
