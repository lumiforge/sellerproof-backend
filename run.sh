FILE_PATHS=(
  "docs/SellerProof API/6 video-upload/complete/test-video.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-1.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/7101f088-f1e1-43c1-b8c5-682f632c7657/64eed634-8701-4e46-8979-9b5ba9f36067/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251212%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251212T001811Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=000645B62E0AA531&x-id=UploadPart&X-Amz-Signature=7e336aa3aa3447517a4e015b554350368d5172a30e23bdf67160ec5433336153"
"https://sellerproof-yc.storage.yandexcloud.net/videos/7101f088-f1e1-43c1-b8c5-682f632c7657/64eed634-8701-4e46-8979-9b5ba9f36067/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251212%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251212T001811Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=000645B62E0AA531&x-id=UploadPart&X-Amz-Signature=c02090581427c0abce8e14663692580bbc88f5a6c754a0e81e655f2ed467a441"
"https://sellerproof-yc.storage.yandexcloud.net/videos/7101f088-f1e1-43c1-b8c5-682f632c7657/64eed634-8701-4e46-8979-9b5ba9f36067/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251212%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251212T001811Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=000645B62E0AA531&x-id=UploadPart&X-Amz-Signature=8d9a84e904c6ac1148f39aca68859b3c7aa318892180dca06cd0e1bbdcb4f4ea"
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