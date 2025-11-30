FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)
# Задай сразу здесь ссылки
PART_URLS=(
    "https://sellerproof-yc.storage.yandexcloud.net/videos/bba849d9-41d2-4c52-a059-f5b42ee16707/b01fac88-f763-4fb7-97e3-54c81a50ffe9/%D1%82%D0%B5%D1%81%D1%82%D0%BE%D0%B2%D0%BE%D0%B5-%D0%B2%D0%B8%D0%B4%D0%B5%D0%BE-%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251130%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251130T163359Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=000644D2547BA582&x-id=UploadPart&X-Amz-Signature=9b15f6ddbfec0765d54ec62a65c629fe57f0fe527c681f5f6476716b9f8923df"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/bba849d9-41d2-4c52-a059-f5b42ee16707/b01fac88-f763-4fb7-97e3-54c81a50ffe9/%D1%82%D0%B5%D1%81%D1%82%D0%BE%D0%B2%D0%BE%D0%B5-%D0%B2%D0%B8%D0%B4%D0%B5%D0%BE-%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251130%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251130T163359Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=000644D2547BA582&x-id=UploadPart&X-Amz-Signature=fc90c9e20bc9969a3744eb6c88f45d9a8b5a81dd0c8e81efc0c26b1b2e2fb98c"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/bba849d9-41d2-4c52-a059-f5b42ee16707/b01fac88-f763-4fb7-97e3-54c81a50ffe9/%D1%82%D0%B5%D1%81%D1%82%D0%BE%D0%B2%D0%BE%D0%B5-%D0%B2%D0%B8%D0%B4%D0%B5%D0%BE-%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251130%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251130T163359Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=000644D2547BA582&x-id=UploadPart&X-Amz-Signature=64f8c81ec6cfacf1cd460c2bd17b8b2271f0a9786903b5294e3cd784e0261344"
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