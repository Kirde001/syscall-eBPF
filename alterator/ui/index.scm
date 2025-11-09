(document:surround "/std/frame")

(vbox
 (margin "10")
 (label text (bold "Инспектор Syscall (ACC)"))
 (label text " ")
 
 (hbox
  (label text "Отслеживать процесс (comm): ")
  
  (combobox name "filter_input" text "*" (on-get-value (form-value "filter_input")))
  
  (button name "save_filter_button" text "Применить")
 )
 (label name "filter_status" text " ")
 
 (label text " ")
 (textbox name "data_display" height 400)

 (label text " ")
 (button name "update_button" text "Обновить данные из БД")
 )

(document:root
  (when loaded (if (defined? 'on-load) (on-load))))
