(document:surround "/std/frame")

(define (do-update)
  (catch/message
   (lambda ()
     (form-update-enum "data_table" (woo-list "/syscall-inspector")))))

(define (init-wazuh-checkbox)
  (catch/message
   (lambda ()
     (let ((data (woo-read-first "/syscall-inspector" 'action "read_wazuh")))
       (form-update-value "wazuh_chk" (woo-get-option data 'wazuh_state))))))

(define (toggle-wazuh)
  (catch/message
   (lambda ()
     (let ((state (form-value "wazuh_chk")))
       (woo-write "/syscall-inspector" 'action "set_wazuh" 'wazuh_state state)))))

(vbox
  (vbox
    align "left"
    
    (label text (bold "Системный мониторинг (eBPF)"))
    (label text "Модуль отслеживания подозрительной активности.")
    (label text " ")

    ;; Блок настроек
    (hbox
      align "left"
      (checkbox name "wazuh_chk" text "Интеграция с Wazuh SIEM" (when toggled (toggle-wazuh)))
      (label text "  (Логи будут отправляться в системный журнал)")
    )
  )

  (label text " ")

  (listbox 
    name "data_table"
    columns 5
    header (vector "Время" "Важность" "Тип события" "Процесс" "Детали")
    row '#((time . "") (severity . "") (type . "") (process . "") (details . ""))
    enumref "/syscall-inspector"
    height 600
  )
  
  (label text " ")
  
  (hbox 
    align "right"
    (button name "update_button" text "Обновить таблицу" (when clicked (do-update)))
  )
)

(document:root
  (when loaded 
    (init-wazuh-checkbox)
    (do-update)))
