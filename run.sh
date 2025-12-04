FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
  "https://sellerproof-yc.storage.yandexcloud.net/videos/c96e2800-411b-4573-890a-2bfec6cd1f85/b27078b6-d90b-4498-a574-0c2bdc008eb0/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T141712Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=00064520FB67E6B2&x-id=UploadPart&X-Amz-Signature=245a5b6dc682c13ea195b70ba51095b1c6e51493c057e74a6e1bceb0cd454d14"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/c96e2800-411b-4573-890a-2bfec6cd1f85/b27078b6-d90b-4498-a574-0c2bdc008eb0/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T141712Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=00064520FB67E6B2&x-id=UploadPart&X-Amz-Signature=7172c08153fa5c7aadb8e3b514123440d49fac8e7d23ddefbe9b23a01c4144ac"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/c96e2800-411b-4573-890a-2bfec6cd1f85/b27078b6-d90b-4498-a574-0c2bdc008eb0/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T141712Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=00064520FB67E6B2&x-id=UploadPart&X-Amz-Signature=d6280b39c3d0ff4a78b63e91abe318ef691c52377430f6e86f4cd9e9372feec2"
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