

1. health
2. Auth -> Register
 - Регистрируются три пользователя: admin, manager, simple user
3. Auth -> Копируем verification_code из user на облаке (для 3х пользователей)
4. Auth -> Login
 - Авторизуются пользователи: admin, manager, simple user и сохраняются 
   - AccessToken
   - RefreshToken
   - OrgId
   - Id
5. Auth -> Logout - После него перелогиниваем admin
6. Auth -> Profile
7. Auth -> Refresh
8. Organization -> Create
 - Создается организация новая организация для админа менеджера и простого пользователя и сохраняется их ID
9. Organization -> Invite
 - Приглашаем менеджера и простого пользователя в основную организацию админа
 - Приглашаем менеджера в новую организацию простого пользователя
 - Пытаемся с ошибкой пригласить админа в новую организацию простого пользователя админом
10. Organization -> Accept 
 - Принимаем приглашение в организацию админа простого пользователя
 - Принимаем приглашение в организацию админа менеджера
 - Принимаем приглашение в организацию простого пользователя менеджера
11. Organization -> Status
12. Organization -> Members 
13. Organization -> Invitations
14. Organization -> Role
15. Organization -> Delete Invitation
16. Video -> Upload -> Initiate
17. Video -> Upload -> URLs
18. Сслыки копируем URLs -> Get upload URLs success with valid JWT и для второго пользователя тоже
19. Оба раза вставляем URLs в run.sh file -> запускаем run.sh (**5 РАЗ**)
20. Из терминала, запускаем run.sh -> копируем etag в docs/SellerProof API/video/upload/complete/2 Complete upload success with valid JWT.bru
24. Complete run
25. Video get: Проверить, что видео действительно существует, статус сменился на completed, и метаданные (размер, имя) корректны.
26. Video search: Проверить, что видео индексируется и его можно найти в списке (поиск по имени или просто листинг).
27. Video download: Проверить (ПРОВЕРИТЬ ССЫЛКУ ИЗ 1), что владелец может получить временную ссылку (presigned URL) на скачивание приватного файла.
28. Video publish: Опубликовать видео (сделать его доступным публично). Это создаст public_token.
29. Video public: Проверить доступ к видео по публичному токену (без авторизации), который был получен на шаге publish.