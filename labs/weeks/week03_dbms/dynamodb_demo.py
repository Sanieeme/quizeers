"""
Week 3 — DynamoDB demo using real boto3 DynamoDB calls, verified against
moto's mocked AWS (no real AWS account needed to prove the code is correct
-- same approach as ../../07_cloud/aws_s3_upload.py).
"""
import boto3


def create_table(dynamodb, table_name="orders"):
    table = dynamodb.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "order_id", "KeyType": "HASH"},  # partition key
        ],
        AttributeDefinitions=[
            {"AttributeName": "order_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    table.wait_until_exists()
    return table


def demo(dynamodb):
    table = create_table(dynamodb)

    # DynamoDB is schema-less beyond the key: each item can have different
    # attributes, unlike a relational row with a fixed set of columns.
    table.put_item(Item={
        "order_id": "A-1001",
        "customer_name": "Alice Ng",
        "items": [{"product": "Widget A", "qty": 3}],
        "country": "South Africa",
    })
    table.put_item(Item={
        "order_id": "A-1002",
        "customer_name": "Bob Smith",
        "items": [{"product": "Widget B", "qty": 1}],
        "country": "USA",
        "gift_wrap": True,  # extra attribute -- no schema migration needed
    })

    print("[dynamodb] Get by partition key (O(1) lookup, no scan needed):")
    resp = table.get_item(Key={"order_id": "A-1001"})
    print(" ", resp["Item"])

    print("\n[dynamodb] Scan for orders with gift_wrap = True (a full-table scan --")
    print("  DynamoDB charges for this differently than a key lookup, which is")
    print("  why access patterns must be designed around the partition key up front):")
    resp = table.scan(FilterExpression=boto3.dynamodb.conditions.Attr("gift_wrap").eq(True))
    for item in resp["Items"]:
        print(" ", item)

    return table


if __name__ == "__main__":
    from moto import mock_aws

    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        demo(dynamodb)
