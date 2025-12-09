(document:surround "/std/frame")

(define (do-update)
  (catch/message
   (lambda ()
     (form-update-enum "data_table" (woo-list "/sysmon")))))

(define (init-config)
  (catch/message
   (lambda ()
     (form-update-enum "log_format" (woo-list "/sysmon" 'action "list_formats"))
     
     (let ((data (woo-read-first "/sysmon" 'action "read_config")))
       (form-update-value-list '("siem_enabled" "log_format") data)))))

(define (save-config)
  (catch/message
   (lambda ()
     (let ((chk (form-value "siem_enabled"))
           (fmt (form-value "log_format")))
       (woo-write "/sysmon" 'action "save_config" 'siem_enabled chk 'log_format fmt)))))

(vbox
  (label text (bold "Системный мониторинг на основе eBPF"))
  (label text " ")

  (hbox
    align "left"
    (checkbox name "siem_enabled" text "Включить генерацию лого Syslog для SIEM " (when toggled (save-config)))
    (label text "      ")
    (label text "Формат логов: ")
    (combobox name "log_format" (when selected (save-config)))
    (label text "      ")
    (button name "update_button" text "Обновить настройки и таблицу" (when clicked (do-update)))
  )

  (label text " ")

  (listbox 
    name "data_table"
    columns 6
    header (vector "Время" "Уровень важности" "Тип события" "Пользователь" "Процесс" "Детали")
    row '#((time . "") (severity . "") (type . "") (username . "") (process . "") (details . ""))
    enumref "/sysmon"
  )
)

(document:root
  (when loaded 
    (init-config)
    (do-update)))
