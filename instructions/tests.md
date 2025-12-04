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
18. Сслыки копируем URLs из всех --> тестов
19. Вставляем URLs в run.sh file -> запускаем run.sh
20. Запускаем run.sh
21. Video -> Upload -> Complete
23. Video -> get
24. Video -> search
25. Video -> download
26. Video -> publish
27. Video -> public
28. Video -> revoke
29. Video -> delete
30. Auth -> Switch Organization