(define-module (ui syscall-inspector ajax)
    :use-module (alterator ajax)
    :use-module (alterator algo)
    :use-module (alterator woo)
    :export (init))

(define (do-update)
  (catch/message
   (lambda ()
     (let ((data (woo-read-first "/syscall-inspector" 'method "read")))
       (let ((message (woo-get-option data 'data)))
         (form-update-value "data_display" message))))))
(define (load-processes)
  (catch/message
   (lambda ()
     (let ((data (woo-call "/syscall-inspector" 'method "get_processes")))
       (form-update-enum "filter_input" data)))))

(define (load-filter)
  (catch/message
   (lambda ()
     (let ((data (woo-read-first "/syscall-inspector" 'method "read_filter")))
       (let ((filter-val (woo-get-option data 'filter)))
         (form-update-value "filter_input" filter-val))))))

(define (save-filter)
  (catch/message
   (lambda ()
     (let ((new-filter (form-value "filter_input")))
       (form-update-value "filter_status" "Применение...")
       
       (let ((data (woo-read-first "/syscall-inspector"
                                 'method "write_filter"
                                 'filter_value new-filter)))
         
         (form-update-value "filter_status" "Фильтр применен!")
         (form-update-value "filter_input" (woo-get-option data 'new_filter))
         (do-update)
       )))))
    

(define (on-load)
  (form-bind "save_filter_button" "click" save-filter)
  (form-bind "update_button" "click" do-update) 
  
  (load-processes)
  (load-filter)
  (do-update))

(define init on-load)
