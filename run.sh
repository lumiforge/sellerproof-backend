FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)
# Задай сразу здесь ссылки
PART_URLS=(
  "https://sellerproof-yc.storage.yandexcloud.net/videos/b59d1580-2c23-493d-8602-9f5becdb75b4/807c79fd-69ef-4ffe-8d4f-a1e3e3967d53/%E6%B5%8B%E8%AF%95-%E8%A7%86%E9%A2%91-%F0%9F%8E%A5.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251201%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251201T121658Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=000644E1EFC0499A&x-id=UploadPart&X-Amz-Signature=6059e03819429c4eb2d305e12cbbc14b6f5d170fa0c6c1373b42af281d63a3d1"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/b59d1580-2c23-493d-8602-9f5becdb75b4/807c79fd-69ef-4ffe-8d4f-a1e3e3967d53/%E6%B5%8B%E8%AF%95-%E8%A7%86%E9%A2%91-%F0%9F%8E%A5.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251201%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251201T121658Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=000644E1EFC0499A&x-id=UploadPart&X-Amz-Signature=0e18c6fa524d54f31b534f88e5838faa074d132edff6ee450022d7416053f122"

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