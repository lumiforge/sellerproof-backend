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
6. Auth -> Login - User login success (verified email)
7. Auth -> Profile
8. Auth -> Refresh
9. Auth -> Forgot Password
10. Сохраняем resetCode 
11. Auth -> Reset Password
12. Auth -> Login (полностью так как Bruno сбрасывает токены Simple и Manager когда resetCode обновляем)
13. Organization -> Create
 - Создается организация новая организация для админа менеджера и простого пользователя и сохраняется их ID
14. Organization -> Invite
 - Приглашаем менеджера и простого пользователя в основную организацию админа
 - Приглашаем менеджера в новую организацию простого пользователя
 - Пытаемся с ошибкой пригласить админа в новую организацию простого пользователя админом
15. Organization -> Accept 
 - Принимаем приглашение в организацию админа простого пользователя
 - Принимаем приглашение в организацию админа менеджера
 - Принимаем приглашение в организацию простого пользователя менеджера
16. Organization -> Status
17. Organization -> Members 
18. Organization -> Invitations
19. Organization -> Role
20. Organization -> Delete Invitation
21. Video -> Upload -> Initiate
22. Video -> Upload -> URLs
23. Сслыки копируем URLs из всех --> тестов
24. Вставляем URLs в run.sh file -> запускаем run.sh
25. Запускаем run.sh
26. Video -> Upload -> Complete
27. Video -> get
28. Video -> search
29. Video -> download
30. Video -> publish
31. Video -> public
32. Video -> revoke
33. Video -> delete
34. Auth -> Switch Organization