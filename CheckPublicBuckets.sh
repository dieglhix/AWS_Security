for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
  echo "Checking bucket: $bucket"
  aws s3api get-bucket-policy-status --bucket "$bucket" --query "PolicyStatus.IsPublic"
done
