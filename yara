rule detect_hashes {
    meta:
        description = "Detecta los hashes 008659a4bb257a2553a42ce170617f26af97a86820c855787ea56e15925a7feb, 04193e2b9a24c7c63914d71bbff1ca8612b089750a5645caa6c143fc0a1c376d y 0ffdeb5f315763a2edd720acafaa9022dba2955ec52f6ac569ce7f5feaed57a1"
author = "Fevar54"
        date = "2023-03-12"
    strings:
        $hash_1 = "008659a4bb257a2553a42ce170617f26af97a86820c855787ea56e15925a7feb"
        $hash_2 = "04193e2b9a24c7c63914d71bbff1ca8612b089750a5645caa6c143fc0a1c376d"
        $hash_3 = "0ffdeb5f315763a2edd720acafaa9022dba2955ec52f6ac569ce7f5feaed57a1"
    condition:
        any of them
}
