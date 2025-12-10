FILE_PATHS=(
  "docs/SellerProof API/6 video-upload/complete/test-video.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-1.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/4cf51fd7-db10-4d67-9472-98733b54bc22/4cee05a0-6d84-4c9d-88a7-62a9f11a27e9/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251210%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251210T093325Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=00064595B61B5914&x-id=UploadPart&X-Amz-Signature=4154dfa2d36d50867aad3835892a6db1a2f34dd2c1634c20e9c799ca7dc34c07"
"https://sellerproof-yc.storage.yandexcloud.net/videos/4cf51fd7-db10-4d67-9472-98733b54bc22/4cee05a0-6d84-4c9d-88a7-62a9f11a27e9/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251210%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251210T093325Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=00064595B61B5914&x-id=UploadPart&X-Amz-Signature=1c39cff59009c261b3d1655ae0c7ccd5700cd42e3c54088bee1ba306a2774ccd"
"https://sellerproof-yc.storage.yandexcloud.net/videos/4cf51fd7-db10-4d67-9472-98733b54bc22/4cee05a0-6d84-4c9d-88a7-62a9f11a27e9/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251210%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251210T093325Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=00064595B61B5914&x-id=UploadPart&X-Amz-Signature=da2c833440aca7ef9f44624bc9f784e1a2f7d3e61f4f1e62249e4fdb332d0f54"
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