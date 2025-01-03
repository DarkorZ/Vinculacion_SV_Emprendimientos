fetch('/direction')
        .then(res => res.json())
        .then(data => {

            let provincias = [];

            var cantones = [
                {
                    provincia: '',
                    canton: ''
                }
            ];

            var parroquias = [
                {
                    id: '',
                    canton: '',
                    parroquia: ''
                }
            ];

            const direction = '';

            data.direction.forEach(places => {
                provincias.push(places.PROVINCIA);
                cantones.push({ provincia: places.PROVINCIA, canton: places.CANTON });
                parroquias.push({ id: places.DIRECCION_ID, canton: places.CANTON, parroquia: places.PARROQUIA });
            });

            // for (let i of cantones) {
            //     console.log('canton: ' + i.canton);
            // }

            let unicosProvincias = Array.from(new Set(provincias));

            // console.log('provincias: ' + unicosProvincias);

            let hash = {};
            cantones = cantones.filter(o => hash[o.canton] ? false : hash[o.canton] = true);
            // console.log(JSON.stringify(cantones));

            //creando los options de direccion
            var areasSelect = document.getElementById('provincia');
            var categoriasSelect = document.getElementById('canton');
            var subCategoriasSelect = document.getElementById('parroquia');

            areasSelect.addEventListener("change", cargarCategorias);
            categoriasSelect.addEventListener("change", cargarSubCategorias);

            unicosProvincias.forEach(function (unicosProvincia) {
                let opcion = document.createElement('option')
                opcion.value = unicosProvincia
                opcion.text = unicosProvincia
                areasSelect.add(opcion)
            })

            function cargarCategorias() {
                categoriasSelect.options.length = 1;
                subCategoriasSelect.options.length = 1;
                cantones
                    .filter(function (canton) {
                        return canton.provincia == this;
                    }, areasSelect.value)
                    .forEach(function (canton) {
                        let opcion = document.createElement('option')
                        opcion.value = canton.canton
                        opcion.text = canton.canton
                        categoriasSelect.add(opcion);
                    });
            }

            function cargarSubCategorias() {
                subCategoriasSelect.options.length = 1;
                parroquias
                    .filter(function (parroquia) {
                        return parroquia.canton == this;
                    }, categoriasSelect.value)
                    .forEach(function (parroquia) {
                        let opcion = document.createElement('option')
                        opcion.value = parroquia.id
                        opcion.text = parroquia.parroquia
                        subCategoriasSelect.add(opcion);
                    });
            }

        });