FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/bd7f7f1f-79f8-470c-9606-a414d408f5d9/0684b498-30ae-407b-8d6a-bda2ad5b3358/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251205%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251205T214742Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006453B63B02F9E&x-id=UploadPart&X-Amz-Signature=d5dc3adcf1140f4841227dfdaa1d52e544427d8206a07feb7bfc802890cebe34"
"https://sellerproof-yc.storage.yandexcloud.net/videos/bd7f7f1f-79f8-470c-9606-a414d408f5d9/0684b498-30ae-407b-8d6a-bda2ad5b3358/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251205%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251205T214742Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006453B63B02F9E&x-id=UploadPart&X-Amz-Signature=196027ad232c852060729d19b99f4e9f87476bab66f2932f8aa73cd6e61c5adc"
"https://sellerproof-yc.storage.yandexcloud.net/videos/bd7f7f1f-79f8-470c-9606-a414d408f5d9/0684b498-30ae-407b-8d6a-bda2ad5b3358/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251205%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251205T214742Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006453B63B02F9E&x-id=UploadPart&X-Amz-Signature=20042025e9e81b7fada3b09a7d6b52975e418df2a7d809abcbd9e7b1c1d8db8f"
)


for i in "${!PART_URLS[@]}"; do
  partIndex=$(( i + 1 ))
  url="${PART_URLS[i]}"
  etagVar="part${partIndex}Etag"

  echo "Загружаем часть ${partIndex}: $url"
  response=$(curl -s -i -X PUT \
    -H "Content-Type: application/octet-stream" \
    --upload-file "${FILE_PATHS[i]}" \
    "$url")

  echo "Ответ заголовков (часть ${partIndex}):"
  echo "$response" | head -n20

  etag=$(echo "$response" | tr -d '\r' | grep -Ei '^ETag:' | sed -E 's/^ETag:[[:space:]]*"(.*)"/\1/i')
  if [ -z "$etag" ]; then
    echo "Ошибка: ETag для части ${partIndex} не найден."
    exit 1
  fi

  echo "Для части ${partIndex} получен ETag: $etag"

done