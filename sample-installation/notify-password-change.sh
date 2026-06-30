curl -i --user ad-pwd-sync:password \
-H "Accept: application/json" \
-H "Content-Type: application/json" \
-X POST http://localhost:8080/midpoint/ws/rest/notifyChange \
--data-binary @notify-password-change.json
