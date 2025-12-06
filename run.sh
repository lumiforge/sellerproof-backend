FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/48577ef1-6de9-428a-affc-d6ca9985c4a2/5dce0d07-4fcc-47b4-8b85-3e5e6114ec9f/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251206%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251206T122132Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006454797EEF537&x-id=UploadPart&X-Amz-Signature=12d64c3e40dbe70e325ecab6e580b98f3e44b69a92b42414e6417451000f07c2"
"https://sellerproof-yc.storage.yandexcloud.net/videos/48577ef1-6de9-428a-affc-d6ca9985c4a2/5dce0d07-4fcc-47b4-8b85-3e5e6114ec9f/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251206%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251206T122132Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006454797EEF537&x-id=UploadPart&X-Amz-Signature=ad6e5d469de270dc86c4fc77b3c749f476708c27e56541a89504909beea88a87"
"https://sellerproof-yc.storage.yandexcloud.net/videos/48577ef1-6de9-428a-affc-d6ca9985c4a2/5dce0d07-4fcc-47b4-8b85-3e5e6114ec9f/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251206%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251206T122132Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006454797EEF537&x-id=UploadPart&X-Amz-Signature=b584e75c415d0c2e1f06e6f9e745fce72614cd4cc681c9c49a7d9556fe43f39f"
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