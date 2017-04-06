/*
 * El paquete ARP Scanner (arp-scan) tiene Copyright (C) 2005-2016 Roy Hills,
 * NTA Monitor Ltd.
 * Modificado por Alberto Avidad Fernandez, para la distro GrX
 * Oficina de Software libre de la Diputacion de Granada
 * Este programa es software libre: se puede redistribuir y / o modificar
 * bajo los términos de la Licencia Pública General de GNU publicada por
 * La Free Software Foundation, ya sea la versión 3 de la Licencia, o
 * (a su elección) cualquier versión posterior.
 * Este programa se distribuye con la esperanza de que sea útil,
 * pero SIN NINGUNA GARANTÍA; Sin la garantía implícita de
 * COMERCIABILIDAD o APTITUD PARA UN PROPÓSITO PARTICULAR. Vea el
 * GNU General Public License para más detalles.
 * Debería haber recibido una copia de la Licencia Pública General de GNU
 * Junto con este programa. Si no es así, consulte <http://www.gnu.org/licenses/>.
 * arp-scan es software libre: Puedes redistribuirlo o modificarlo
 * bajo los terminos de GNU General Public License como se indica en
 * la Free Software Foundation, version 3 de la licencia, o
 * posteriores.
 *
 * arp-scan -- Escaneador de paquetes ARP
 *
 * Autor:	Roy Hills
 * Fecha:	13 Octubre 2005
 * Modificado:  Alberto Avidad Fernandez (OSL)
 * Fecha:	25 Marzo 2017
 * Usar:
 *
 *    arp-scan [opciones] [host...]
 *
 * Descripcion:
 *
 * arp-scan manda paquetes ARP a hosts especificos y muestra si alguno responde
 *
 * El protocolo ARP esta definido en RFC 826 Ethernet Address Resolution Protocol
 *
 */

#include "arp-scan.h"

/* Global variables */
static host_entry *helist = NULL;	/* Array de host entries */
static host_entry **helistptr;		/* Array de punteros para host entries */
static host_entry **cursor;		/* Puntero to current host entry ptr */
static unsigned num_hosts = 0;		/* Numero de entradas en la list */
static unsigned responders = 0;		/* Numero de hosts con respuesta */
static unsigned live_count;		/* Numero de entradas esperando respuesta */
static int verbose=0;			/* Nivel de detalle*/
static char filename[MAXLINE];		/* Nombre del archivo de destino */
static int filename_flag=0;		/* Indica si usamos un fichero de destino */
static int random_flag=0;		/* Aleatoriza la lista */
static int numeric_flag=0;		/* Solo direcciones IP */
static unsigned interval=0;		/* Intervalo deseado entre paquetes */
static unsigned bandwidth=DEFAULT_BANDWIDTH; /* Ancho de banda en bits por segundo */
static unsigned retry = DEFAULT_RETRY;	/* Numero de intentos */
static unsigned timeout = DEFAULT_TIMEOUT; /* Timeout por host */
static float backoff_factor = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
static int snaplen = SNAPLEN;		/* Pcap longitud de snap */
static char *if_name=NULL;		/* Nombre de interfaz, ejem. "eth0" */
static int quiet_flag=0;		/* No decodifica el paquete */
static int ignore_dups=0;		/* No mostrar paquetes duplicados */
static uint32_t arp_spa;		/* Direccion de IP origen */
static int arp_spa_flag=0;		/* Direccion de IP origen especificada */
static int arp_spa_is_tpa=0;		/* Direccion de IP origen es la misma que destino */
static unsigned char arp_sha[ETH_ALEN];	/* Direccion de origen MAC de Ethernet */
static int arp_sha_flag=0;		/* Direccion de origen MAC especificada */
static char ouifilename[MAXLINE];	/* OUI nombre de fichero */
static char iabfilename[MAXLINE];	/* IAB nombre de fichero */
static char macfilename[MAXLINE];	/* MAC nombre de fichero */
static char pcap_savefile[MAXLINE];	/* pcap savefile nombre de fichero */
static int arp_op=DEFAULT_ARP_OP;	/* ARP Codigo de operacion */
static int arp_hrd=DEFAULT_ARP_HRD;	/* ARP tipo de hardware */
static int arp_pro=DEFAULT_ARP_PRO;	/* ARP protocolo */
static int arp_hln=DEFAULT_ARP_HLN;	/* Tamaño de direccion Hardware */
static int arp_pln=DEFAULT_ARP_PLN;	/* Tamaño de la direccion de protocolo */
static int eth_pro=DEFAULT_ETH_PRO;	/* Tipo de protocolo Ethernet */
static unsigned char arp_tha[6] = {0, 0, 0, 0, 0, 0};
static unsigned char target_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static unsigned char source_mac[6];
static int source_mac_flag = 0;
static unsigned char *padding=NULL;
static size_t padding_len=0;
static int grx_flag=0;			/* Parametro de búsqueda para grx*/
static int octeto=0;			/* Octeto para formar la ip*/
static int localnet_flag=0;		/* Escanear la red local */
static int llc_flag=0;			/* Usar 802.2 LLC con SNAP */
static int ieee_8021q_vlan=-1;		/* Usar etiquetado 802.1Q VLAN si >= 0 */
static int pkt_write_file_flag=0;	/* Grabar paquetes a fichero flag */
static int pkt_read_file_flag=0;	/* Leer paquetes desde el fichero flag */
static char pkt_filename[MAXLINE];	/* Leer/Grabar paquetes al fichero filename */
static int write_pkt_to_file=0;		/* Grabar paquetes al fichero para debugging */
static int rtt_flag=0;			/* Mostrar tiempo de ida y vuelta */
static pcap_dumper_t *pcap_dump_handle = NULL;	/* pcap manejador de fichero para grabar */
static int plain_flag=0;		/* Solo muestra informacion de host */
unsigned int random_seed=0;

int
main(int argc, char *argv[]) {
   struct timeval now;
   struct timeval diff;         /* Diferencia entre dos intervalos de tiempo */
   int select_timeout;          /* Seleciona timeout */
   ARP_UINT64 loop_timediff;    /* Tiempo desde el ultimo paquete mandado por nosotros */
   ARP_UINT64 host_timediff; /* Tiempo desde el ultimo paquete mandado a este host (nosotros) */
   struct timeval last_packet_time;     /* Tiempo desde que el ultimo paquete ha sido enviado */
   int req_interval;		/* Intervalo por paquete solicitado */
   int cum_err=0;               /* Error de tiempo acumulado */
   struct timeval start_time;   /* Program start time */
   struct timeval end_time;     /* Program end time */
   struct timeval elapsed_time; /* Elapsed time as timeval */
   double elapsed_seconds;      /* Elapsed time in seconds */
   int reset_cum_err;
   int pass_no = 0;
   int first_timeout=1;
   unsigned i;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct bpf_program filter;
   char *filter_string;
   bpf_u_int32 netmask;
   bpf_u_int32 localnet;
   int datalink;
   int get_addr_status = 0;
   int pcap_fd;			/* Pcap descriptor del fichero */
   unsigned char interface_mac[ETH_ALEN];
   pcap_t *pcap_handle;		/* pcap manejador */
/*
 *      Inicializamos los ficheros a cadenas vacias.
 */
   ouifilename[0] = '\0';
   iabfilename[0] = '\0';
   macfilename[0] = '\0';
   pcap_savefile[0] = '\0';
/*
 *      Procesamos la opciones.
 */
   process_options(argc, argv);
/*
 *      Obtener la hora de inicio del programa para las estadísticas que se muestran al finalizar.
 */
   Gettimeofday(&start_time);
/*
 * Obtener detalles de la interfaz de red a menos que leamos
 * desde un archivo pcap o escribiendo en un archivo binario.
 */
   if (!pkt_read_file_flag && !pkt_write_file_flag) {
/*
 * Determinar la interfaz de red para su uso. Si se especificó la interfaz
 * con la opción --interface entonces use eso, de lo contrario use
 * pcap_lookupdev () para seleccionar una interfaz adecuada.
 */
   if (!if_name) {
      if (!(if_name=pcap_lookupdev(errbuf))) {
         err_msg("pcap_lookupdev: %s", errbuf);
      }
   }
/*

 * Obtenga la dirección MAC de la interfaz seleccionada y utilice esta
 * como predeterminado para las direcciones de hardware de origen en el encabezado de trama
 * y el paquete ARP si el usuario no ha especificado sus valores.
 * Muere con un error si no podemos obtener la dirección MAC, ya que
 * indica que la interfaz no tiene una dirección MAC, por lo que es
 * probablemente no es un tipo de interfaz compatible.
 */
      get_hardware_address(if_name, interface_mac);
      if (interface_mac[0]==0 && interface_mac[1]==0 &&
          interface_mac[2]==0 && interface_mac[3]==0 &&
          interface_mac[4]==0 && interface_mac[5]==0) {
         err_msg("ERROR: No ha sido posible obtener la direccion MAC para la interfaz %s",
                 if_name);
      }
      if (source_mac_flag == 0)
         memcpy(source_mac, interface_mac, ETH_ALEN);
      if (arp_sha_flag == 0)
         memcpy(arp_sha, interface_mac, ETH_ALEN);
/*
 * Si el usuario no ha especificado la dirección de origen ARP, obtenga
 * interfaz de la dirección IP y utilizarlo como valor predeterminado.
 */
      if (arp_spa_flag == 0) {
         get_addr_status = get_source_ip(if_name, &arp_spa);
         if (get_addr_status == -1) {
            warn_msg("ATENCION: No ha sido posible obtener la direccion para la interfaz %s. "
                     "Usando 0.0.0.0 para", if_name);
            warn_msg("la direccion origen, probablemente no es la que quieres.");
            warn_msg("Configure %s con una dirección IP o especificada manualmente", if_name);
            warn_msg("con la opcion --arpspa");
            memset(&arp_spa, '\0', sizeof(arp_spa));
         }
      }
   }
/*
 * Abra el dispositivo de red para leer con pcap, o el archivo pcap si
 * han especificado --readpktfromfile. Si estamos escribiendo paquetes a un archivo binario
 * a continuación, establezca pcap_handle a NULL ya que no es necesario leer los paquetes en
 * este caso.
 */
   if (pkt_read_file_flag) {
      if (!(pcap_handle = pcap_open_offline(pkt_filename, errbuf)))
         err_msg("pcap_open_offline: %s", errbuf);
   } else if (!pkt_write_file_flag) {
      if (!(pcap_handle = pcap_create(if_name, errbuf)))
         err_msg("pcap_create: %s", errbuf);
      if ((pcap_set_snaplen(pcap_handle, snaplen)) < 0)
         err_msg("pcap_set_snaplen: %s", pcap_geterr(pcap_handle));
      if ((pcap_set_promisc(pcap_handle, PROMISC)) < 0)
         err_msg("pcap_set_promisc: %s", pcap_geterr(pcap_handle));
      if ((pcap_set_timeout(pcap_handle, TO_MS)) < 0)
         err_msg("pcap_set_timeout: %s", pcap_geterr(pcap_handle));
      if ((pcap_activate(pcap_handle)) < 0)
         err_msg("pcap_activate: %s", pcap_geterr(pcap_handle));
   } else {
      pcap_handle = NULL;
   }
/*
 * Si estamos leyendo datos con pcap, obtenemos y mostramos los detalles del datalink
 */
   if (pcap_handle) {
      if ((datalink=pcap_datalink(pcap_handle)) < 0)
         err_msg("pcap_datalink: %s", pcap_geterr(pcap_handle));
      if (!plain_flag) {
         printf("Interfaz: %s, tipo de enlace de datos: %s (%s)\n",
                pkt_read_file_flag ? "savefile" : if_name,
                pcap_datalink_val_to_name(datalink),
                pcap_datalink_val_to_description(datalink));
      }
      if (datalink != DLT_EN10MB) {
         warn_msg("PELIGRO: Tipo de enlace de datos no soportado");
      }
   }
/*
 * Si estamos leyendo desde un dispositivo de red, a continuación, obtener el archivo asociado
 * descriptor y configurarlo, determinar la interfaz de la red IP y
 * netmask, e instale un filtro pcap para recibir sólo respuestas ARP.
 * Si estamos leyendo desde un archivo pcap, o escribiendo en un archivo binario, simplemente
 * establecer el descriptor de archivo a -1 para indicar que no está asociado
 * con un dispositivo de red.
 */
   if (!pkt_read_file_flag && !pkt_write_file_flag) {
      if ((pcap_fd=pcap_get_selectable_fd(pcap_handle)) < 0)
         err_msg("pcap_fileno: %s", pcap_geterr(pcap_handle));
      if ((pcap_setnonblock(pcap_handle, 1, errbuf)) < 0)
         err_msg("pcap_setnonblock: %s", errbuf);
/*
 * Para la implementación de pcap BPF, configure el dispositivo BPF en modo inmediato,
 * de lo contrario almacenará las respuestas.
 */
#ifdef ARP_PCAP_BPF
#ifdef BIOCIMMEDIATE
      {
         unsigned int one = 1;

         if (ioctl(pcap_fd, BIOCIMMEDIATE, &one) < 0)
            err_sys("ioctl BIOCIMMEDIATE");
      }
#endif /* BIOCIMMEDIATE */
#endif /* ARP_PCAP_BPF */
/*
 * Para la implementación de pcap DLPI en Solaris, establezca el tiempo de espera bufmod en
 * cero. Esto tiene el efecto secundario de establecer el tamaño de trozo a cero como
 * bien, así que bufmod pasará todos los mensajes entrantes encendido inmediatamente.
 */
#ifdef ARP_PCAP_DLPI
      {
         struct timeval time_zero = {0, 0};

         if (ioctl(pcap_fd, SBIOCSTIME, &time_zero) < 0)
            err_sys("ioctl SBIOCSTIME");
      }
#endif
      if (pcap_lookupnet(if_name, &localnet, &netmask, errbuf) < 0) {
         memset(&localnet, '\0', sizeof(localnet));
         memset(&netmask, '\0', sizeof(netmask));
         if (localnet_flag) {
            warn_msg("ERROR: No puedo obtener la direccion IP y la mascara de red");
            err_msg("ERROR: pcap_lookupnet: %s", errbuf);
         }
      }
/*
 * La cadena de filtro selecciona los paquetes dirigidos a la dirección de origen ARP
 * que son paquetes Ethernet-II ARP, paquetes 802.3 LLC / SNAP ARP,
 * 802.1Q marcó paquetes ARP o 802.1Q marcó paquetes 802.3 LLC / SNAP ARP.
 */
      filter_string=make_message("ether dst %.2x:%.2x:%.2x:%.2x:%.2x:%.2x and "
                                 "(arp or (ether[14:4]=0xaaaa0300 and "
                                 "ether[20:2]=0x0806) or (ether[12:2]=0x8100 "
                                 "and ether[16:2]=0x0806) or "
                                 "(ether[12:2]=0x8100 and "
                                 "ether[18:4]=0xaaaa0300 and "
                                 "ether[24:2]=0x0806))",
                                 arp_sha[0], arp_sha[1],
                                 arp_sha[2], arp_sha[3],
                                 arp_sha[4], arp_sha[5]);
      if (verbose > 1)
         warn_msg("DEBUG: pcap filtro de cadena: \"%s\"", filter_string);
      if ((pcap_compile(pcap_handle, &filter, filter_string, OPTIMISE,
           netmask)) < 0)
         err_msg("pcap_compile: %s", pcap_geterr(pcap_handle));
      free(filter_string);
      if ((pcap_setfilter(pcap_handle, &filter)) < 0)
         err_msg("pcap_setfilter: %s", pcap_geterr(pcap_handle));
   } else {	/* Leyendo paquetes desde un fichero */
      pcap_fd = -1;
   }
/*
 *      Dropea privilegios SUID.
 */
   if ((setuid(getuid())) < 0) {
      err_sys("setuid");
   }
/*
 * Opción --pcapsavefile (-W) fue especificada
 */
   if (*pcap_savefile != '\0') {
      if (!(pcap_dump_handle=pcap_dump_open(pcap_handle, pcap_savefile))) {
         err_msg("pcap_dump_open: %s", pcap_geterr(pcap_handle));
      }
   }
/*
 * Compruebe que la combinación de opciones y argumentos especificados es
 * válido. */
   if (interval && bandwidth != DEFAULT_BANDWIDTH)
      err_msg("ERROR: No puedes especificar a la vez --bandwidth e --interval.");
   if (localnet_flag) {
      if ((argc - optind) > 0)
         err_msg("ERROR: No puedes especificar objetivos con la opcion --localnet activada");
      if (filename_flag)
         err_msg("ERROR: No podemos especificar a la vez --file y la opcion --localnet");
   }
/*
 * Si no estamos leyendo de un archivo, y --localnet no fue especificado, entonces
 * debemos tener algunos hosts dados como argumentos de línea de comandos.
 */
   if (!filename_flag && !localnet_flag)
      if ((argc - optind) < 1)
         usage(EXIT_FAILURE, 0);
/*
 * Crear tabla de hash de MAC / Vendedor si quiet no tiene efecto.
 */
   if (!quiet_flag) {
      char *fn;
      int count;

      if ((hcreate(HASH_TABLE_SIZE)) == 0)
         err_sys("hcreate");

      fn = get_mac_vendor_filename(ouifilename, DATADIR, OUIFILENAME);
      count = add_mac_vendor(fn);
      if (verbose > 1 && count > 0)
         warn_msg("DEBUG: Cargado %d IEEE OUI/Vendor entradas desde %s.",
                  count, fn);
      free(fn);

      fn = get_mac_vendor_filename(iabfilename, DATADIR, IABFILENAME);
      count = add_mac_vendor(fn);
      if (verbose > 1 && count > 0)
         warn_msg("DEBUG: Cargado %d IEEE IAB/Vendor entradas desde %s.",
                  count, fn);
      free(fn);

      fn = get_mac_vendor_filename(macfilename, DATADIR, MACFILENAME);
      count = add_mac_vendor(fn);
      if (verbose > 1 && count > 0)
         warn_msg("DEBUG: Cargado %d MAC/Vendor entradas desde %s.",
                  count, fn);
      free(fn);
   }
/*
 * Rellena la lista desde el archivo especificado en --file, o
 * desde la dirección de la interfaz y la máscara si se especificó --localnet, o
 * de lo contrario, de los argumentos restantes de la línea de comandos.
 */
   if (filename_flag) { /* Rellena la lista desde fichero */
      FILE *fp;
      char line[MAXLINE];
      char *cp;

      if ((strcmp(filename, "-")) == 0) {       /* Si ponemos "-" usaremos stdin */
         fp = stdin;
      } else {
         if ((fp = fopen(filename, "r")) == NULL) {
            err_sys("fopen");
         }
      }

      while (fgets(line, MAXLINE, fp)) {
         for (cp = line; !isspace((unsigned char)*cp) && *cp != '\0'; cp++)
            ;
         *cp = '\0';
         add_host_pattern(line, timeout);
      }
      if (fp != stdin) {
         fclose(fp);
      }
   } else if (localnet_flag) {	/* Rellena la lista desde i/f addr & mask */
      struct in_addr if_network;
      struct in_addr if_netmask;
      char *c_network;
      char *c_netmask;
      const char *cp;
      char localnet_descr[32];

      if_network.s_addr = localnet;
      if_netmask.s_addr = netmask;
      cp = my_ntoa(if_network);
      c_network = make_message("%s", cp);
      cp = my_ntoa(if_netmask);
      c_netmask = make_message("%s", cp);
      snprintf(localnet_descr, 32, "%s:%s", c_network, c_netmask);
      free(c_network);
      free(c_netmask);

      if (verbose) {
         warn_msg("Usando %s para red local", localnet_descr);
      }
      add_host_pattern(localnet_descr, timeout);
   } else {             /* Rellena la lista desde la linea de comandos */
      argv=&argv[optind];
      while (*argv) {
         add_host_pattern(*argv, timeout);
         argv++;
      }
   }
/*
 * Comprueba que tenemos al menos una entrada en la lista.
 */
   if (!num_hosts)
      err_msg("ERROR: No hay hosts para procesar.");
/*
 * Si se ha especificado --writepkttofile, abra el archivo de salida especificado.
 */
   if (pkt_write_file_flag) {
      write_pkt_to_file = open(pkt_filename, O_WRONLY|O_CREAT|O_TRUNC, 0666);
      if (write_pkt_to_file == -1)
         err_sys("open %s", pkt_filename);
   }
/*
 * Crear e inicializar la matriz de punteros a las entradas de host.
 */
   helistptr = Malloc(num_hosts * sizeof(host_entry *));
   for (i=0; i<num_hosts; i++)
      helistptr[i] = &helist[i];
/*
 * Aleatoriza la lista si es necesario.
 * Usa el algoritmo aleatorio de Knuth.
 */
   if (random_flag) {
      int r;
      host_entry *temp;
/*
 * Generador de números aleatorios de semillas.
 * Si se ha especificado la semilla aleatoria (no es cero), entonces usa eso.
 * De lo contrario, siembra el RNG con un valor impredecible. */

      if (!random_seed) {
         struct timeval tv;

         Gettimeofday(&tv);
         random_seed = tv.tv_usec ^ getpid();	/* Valor impredecible */
      }
      init_genrand(random_seed);

      for (i=num_hosts-1; i>0; i--) {
         r = (int)(genrand_real2() * i);  /* 0<=r<i */
         temp = helistptr[i];
         helistptr[i] = helistptr[r];
         helistptr[r] = temp;
      }
   }
/*
 * Establece el puntero del host actual (cursor) al inicio de la lista, pone a cero
 * el último paquete enviado de tiempo, y establece el tiempo hasta ahora. */
   live_count = num_hosts;
   cursor = helistptr;
   last_packet_time.tv_sec=0;
   last_packet_time.tv_usec=0;
/*
 * Calcular el intervalo requerido para lograr el ancho de banda para la salida requerida
 *  a menos que el intervalo se especifique manualmente con --interval.rval.
 */
   if (!interval) {
      size_t packet_out_len;

      packet_out_len=send_packet(NULL, NULL, NULL,0); /* Get packet data size */
      if (packet_out_len < MINIMUM_FRAME_SIZE)
         packet_out_len = MINIMUM_FRAME_SIZE;   /* Adjust to minimum size */
      packet_out_len += PACKET_OVERHEAD;	/* Add layer 2 overhead */
      interval = ((ARP_UINT64)packet_out_len * 8 * 1000000) / bandwidth;
      if (verbose > 1) {
         warn_msg("DEBUG: pkt len=%u bytes, ancho de banda=%u bps, intervalo=%u us",
                  packet_out_len, bandwidth, interval);
      }
   }
/*
 *      Muestra mensaje inicial.
 */
   if (!plain_flag) {
      printf("Comenzando %s con %u hosts (https://incidencias.dipgra.es/arp-scan)\n",
          PACKAGE_STRING, num_hosts);
   }
/*
 * Muestra las listas si el ajuste detallado es 3 o más.
 */
   if (verbose > 2)
      dump_list();
/*
 * Bucle principal: envía paquetes a todos los hosts en orden hasta que una respuesta
 * Ha sido recibida o el host ha agotado su límite de reintento.
 *
 * El bucle se cierra cuando todos los hosts han respondido o agotado el tiempo de espera.
 */
   reset_cum_err = 1;
   req_interval = interval;
   while (live_count) {
/*
 * Obtener la hora actual y calcular los deltas desde el último paquete y el 
 * paquete pasado para es host.
 */
      Gettimeofday(&now);
/*
 * Si el último paquete se envió hace más de un intervalo, entonces podemos
 * envíar un paquete al host actual.
 */
      timeval_diff(&now, &last_packet_time, &diff);
      loop_timediff = (ARP_UINT64)1000000*diff.tv_sec + diff.tv_usec;
      if (loop_timediff >= (unsigned)req_interval) {
/*
 * Si el último paquete enviado a este host fue enviado con un timeout cumplido,
 * entonces podemos enviar un paquete nuevo.
 */
         timeval_diff(&now, &((*cursor)->last_send_time), &diff);
         host_timediff = (ARP_UINT64)1000000*diff.tv_sec + diff.tv_usec;
         if (host_timediff >= (*cursor)->timeout) {
            if (reset_cum_err) {
               cum_err = 0;
               req_interval = interval;
               reset_cum_err = 0;
            } else {
               cum_err += loop_timediff - interval;
               if (req_interval >= cum_err) {
                  req_interval = req_interval - cum_err;
               } else {
                  req_interval = 0;
               }
            }
            select_timeout = req_interval;
/*
 * Si hemos superado nuestro límite de reintentos, entonces este host ha expirado
 * y lo eliminamos de la lista. De lo contrario, aumenta el tiempo de espera
 * si este no es el primer paquete enviado a este host y envia un paquete.
 */
            if (verbose && (*cursor)->num_sent > pass_no) {
               warn_msg("---\tPass %d complete", pass_no+1);
               pass_no = (*cursor)->num_sent;
            }
            if ((*cursor)->num_sent >= retry) {
               if (verbose > 1)
                  warn_msg("---\tQuitando host %s - Timeout",
                            my_ntoa((*cursor)->addr));
               remove_host(cursor);     /* Llama automaticamente a calls advance_cursor() */
               if (first_timeout) {
                  timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                  host_timediff = (ARP_UINT64)1000000*diff.tv_sec +
                                  diff.tv_usec;
                  while (host_timediff >= (*cursor)->timeout && live_count) {
                     if ((*cursor)->live) {
                        if (verbose > 1)
                           warn_msg("---\tQuitando host %s - Catch-Up Timeout",
                                    my_ntoa((*cursor)->addr));
                        remove_host(cursor);
                     } else {
                        advance_cursor();
                     }
                     timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                     host_timediff = (ARP_UINT64)1000000*diff.tv_sec +
                                     diff.tv_usec;
                  }
                  first_timeout=0;
               }
               Gettimeofday(&last_packet_time);
            } else {    /* Límite de reintento no alcanzado para este host*/
               if ((*cursor)->num_sent)
                  (*cursor)->timeout *= backoff_factor;
               send_packet(pcap_handle, *cursor, &last_packet_time, octeto);
               advance_cursor();
            }
         } else {       /* No podemos mandar un paquete a este host todavia */
/*
 * Tenga en cuenta que no hay ningún punto llamando a advance_cursor () aquí porque si
 * Host n no está listo para enviar, entonces host n + 1 tampoco estará listo.
 */
            select_timeout = (*cursor)->timeout - host_timediff;
            reset_cum_err = 1;  /* Errores acumulados cero */
         } /* Termina si */
      } else {          /* No podemos mandar un paquete todavia */
         select_timeout = req_interval - loop_timediff;
      } /* Termina si */
      recvfrom_wto(pcap_fd, select_timeout, pcap_handle);
   } /* Termina mientras */

   if (!plain_flag) {
      printf("\n");        /* Nos aseguramos tener una linea en blanco */
   }

   clean_up(pcap_handle);
   if (write_pkt_to_file)
      close(write_pkt_to_file);

   Gettimeofday(&end_time);
   timeval_diff(&end_time, &start_time, &elapsed_time);
   elapsed_seconds = (elapsed_time.tv_sec*1000 +
                      elapsed_time.tv_usec/1000) / 1000.0;

   if (!plain_flag) {
      printf("Resultado %s: %u hosts escaneados en %.3f segundos (%.2f hosts/segundo). %u han respondido\n",
             PACKAGE_STRING, num_hosts, elapsed_seconds,
             num_hosts/elapsed_seconds, responders);
   }
   return 0;
}

/*
 *	display_packet -- Comprobar y mostrar el paquete Recibido
 *
 *	Entradas:
 *
 *	he		La entrada de hosts correspondiente al paquete Recibido
 *	arpei		Estructura de paquete ARP
 *	extra_data	Datos extra del paquete ARP (relleno)
 *	extra_data_len	Tamaño de los datos extra
 *	framing		Framing type (e.g. Ethernet II, LLC)
 *	vlan_id		Identificador 802.1Q VLAN, o -1 si no 802.1Q
 *	frame_hdr	La cabecera de Ethernet
 *	pcap_header	La estructura de cabecera PCAP
 *
 *      Devuelve:
 *
 *      Nada.
 *
 * Esto comprueba el paquete Recibido y muestra detalles de lo que
 * fue Recibido en el formato: <Dirección IP> <TAB> <Detalles>.
 */
void
display_packet(host_entry *he, arp_ether_ipv4 *arpei,
               const unsigned char *extra_data, size_t extra_data_len,
               int framing, int vlan_id, ether_hdr *frame_hdr,
               const struct pcap_pkthdr *pcap_header) {
   char *msg;
   char *cp;
   char *cp2;
   int nonzero=0;
/*
 *	Establecer msg a la dirección IP de la host entry y tab.
 */
   msg = make_message("%s\t", my_ntoa(he->addr));
/*
 *	Decodifica el paquete ARP
 */
   cp = msg;
   msg = make_message("%s%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", cp,
                      arpei->ar_sha[0], arpei->ar_sha[1],
                      arpei->ar_sha[2], arpei->ar_sha[3],
                      arpei->ar_sha[4], arpei->ar_sha[5]);
   free(cp);
/*

 * Compruebe que la dirección de origen en el encabezado de trama Ethernet es la misma
 * que ar$sha en el paquete ARP, y mostrar la dirección de origen Ethernet
 * si es diferente.
 */
   if ((memcmp(arpei->ar_sha, frame_hdr->src_addr, ETH_ALEN)) != 0) {
      cp = msg;
      msg = make_message("%s (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x)", cp,
                         frame_hdr->src_addr[0], frame_hdr->src_addr[1],
                         frame_hdr->src_addr[2], frame_hdr->src_addr[3],
                         frame_hdr->src_addr[4], frame_hdr->src_addr[5]);
      free(cp);
   }
/*
 * Buscar proveedor en la tabla de hash y añadir al mensaje si se ha indicado
 */
   if (!quiet_flag) {
      char oui_string[13];	/* Espacio para todo hw addr plus NULL */
      const char *vendor=NULL;
      int oui_end=12;
      ENTRY hash_query;
      ENTRY *hash_result;

      snprintf(oui_string, 13, "%.2X%.2X%.2X%.2X%.2X%.2X",
               arpei->ar_sha[0], arpei->ar_sha[1], arpei->ar_sha[2],
               arpei->ar_sha[3], arpei->ar_sha[4], arpei->ar_sha[5]);
      while (vendor == NULL && oui_end > 1) {
         oui_string[oui_end] = '\0';	/* Truncar la cadena oui */
         hash_query.key = oui_string;
         hash_result = hsearch(hash_query, FIND);
         if (hash_result) {
            vendor = hash_result->data;
         } else {
            vendor = NULL;
         }
         oui_end--;
      }
      cp = msg;
      if (vendor)
         msg = make_message("%s\t%s", cp, vendor);
      else
         msg = make_message("%s\t%s", cp, "(Unknown)");
      free(cp);
/*
 * Comprueba que cualquier dato después del paquete ARP es cero.
 * Si es distinto de cero y se selecciona verbose, imprima los datos de relleno.
 */
      if (extra_data_len > 0) {
         unsigned i;
         const unsigned char *ucp = extra_data;

         for (i=0; i<extra_data_len; i++) {
            if (ucp[i] != '\0') {
               nonzero=1;
               break;
            }
         }
      }
      if (nonzero && verbose) {
         cp = msg;
         cp2 = hexstring(extra_data, extra_data_len);
         msg = make_message("%s\tPadding=%s", cp, cp2);
         free(cp2);
         free(cp);
      }
/*
 *	Si el tipo de frame no es Ethernet II, informa del tipo de frame.
 */
      if (framing != FRAMING_ETHERNET_II) {
         cp = msg;
         if (framing == FRAMING_LLC_SNAP) {
            msg = make_message("%s (802.2 LLC/SNAP)", cp);
         }
         free(cp);
      }
/*
 *	Si el paquete usa etiquetado 802.1Q VLAN, muestra el VLAN ID.
 */
      if (vlan_id != -1) {
         cp = msg;
         msg = make_message("%s (802.1Q VLAN=%d)", cp, vlan_id);
         free(cp);
      }
/*
 * Si el tipo de protocolo ARP no es IP (0x0800), infórmelo.
 * Esto puede ocurrir con respuestas de ARP de encapsulación con trailer.
 */
      if (ntohs(arpei->ar_pro) != 0x0800) {
         cp = msg;
         msg = make_message("%s (ARP Proto=0x%04x)", cp, ntohs(arpei->ar_pro));
         free(cp);
      }
/*
 *      Si la host entry no esta viva, entonces la mostramos como duplicada.
 */
      if (!he->live) {
         cp = msg;
         msg = make_message("%s (DUP: %u)", cp, he->num_recv);
         free(cp);
      }
/*
 *	If the rtt_flag is set, calculate and report the packet round-trip
 *	time.
 */
      if (rtt_flag) {
         struct timeval rtt;
         struct timeval pcap_timestamp;
         unsigned long rtt_us; /* round-trip time in microseconds */
/*
 * We can't pass a Puntero to pcap_header->ts directly to timeval_diff
 * because it's not guaranteed to have the same size as a struct timeval.
 * E.g. OpenBSD 5.1 on amd64.
 */
         pcap_timestamp.tv_sec = pcap_header->ts.tv_sec;
         pcap_timestamp.tv_usec = pcap_header->ts.tv_usec;
         timeval_diff(&pcap_timestamp, &(he->last_send_time), &rtt);
         rtt_us = rtt.tv_sec * 1000000 + rtt.tv_usec;
         cp=msg;
         msg=make_message("%s\tRTT=%lu.%03lu ms", cp, rtt_us/1000, rtt_us%1000);
         free(cp);
      }
   }	/* End if (!quiet_flag) */
/*
 *	Print the message.
 */
   printf("%s\n", msg);
   free(msg);
}

/*
 *	send_packet -- Construct and send a packet to the specified host
 *
 *	Inputs:
 *
 *	pcap_handle	Pcap handle
 *	he		Host entry to send to. If NULL, then no packet is sent
 *	last_packet_time	Time when last packet was sent
 *
 *      Returns:
 *
 *      The size of the packet that was sent.
 *
 *      This constructs an appropriate packet and sends it to the host
 *      identified by "he" using the socket "s". It also updates the
 *	"last_send_time" field for the host entry.
 *
 *	If we are using the undocumented --writepkttofile option, then we
 *	write the packet to the write_pkt_to_file file descriptor instead of
 *	transmitting it on the network.
 *
 *	If we are using the undocumented --readpktfromfile option, then we
 *	don't send anything.
 */
int
send_packet(pcap_t *pcap_handle, host_entry *he,
            struct timeval *last_packet_time, int oct) {
   unsigned char buf[MAX_FRAME];
   size_t buflen;
   ether_hdr frame_hdr;
   arp_ether_ipv4 arpei;
   int nsent = 0;
   int b1, b2, b3, b4;
   struct in_addr dire;
   char res[20];

/*
 *	Construct Ethernet frame header
 */
   memcpy(frame_hdr.dest_addr, target_mac, ETH_ALEN);
   memcpy(frame_hdr.src_addr, source_mac, ETH_ALEN);
   frame_hdr.frame_type = htons(eth_pro);
/*
 *	Construct the ARP Header.
 */
   memset(&arpei, '\0', sizeof(arp_ether_ipv4));
   arpei.ar_hrd = htons(arp_hrd);
   arpei.ar_pro = htons(arp_pro);
   arpei.ar_hln = arp_hln;
   arpei.ar_pln = arp_pln;
   arpei.ar_op = htons(arp_op);
   memcpy(arpei.ar_sha, arp_sha, ETH_ALEN);
   memcpy(arpei.ar_tha, arp_tha, ETH_ALEN);

   if (he)
      arpei.ar_tip = he->addr.s_addr;

   if (arp_spa_is_tpa) {
      if (he) {
         arpei.ar_sip = he->addr.s_addr;
      }
   } else {
	if (grx_flag){
	   //De la ip de destino cambiamos el ultimo octeto y le ponemos el 
	   //valor de oct, que le pasamos por parámetro 
	   b1 = oct;
	   b2 = (arpei.ar_tip & 0x00ff0000) >> 16;
	   b3 = (arpei.ar_tip & 0x0000ff00) >> 8;
	   b4 = (arpei.ar_tip & 0x000000ff);
	   snprintf(res,20 ,"%d%s%d%s%d%s%d", b4,".",b3,".",b2,".",b1);
	   inet_pton(AF_INET, res , &dire);
	   arpei.ar_sip=dire.s_addr;
        }
	else{
	      arpei.ar_sip = arp_spa;
	    }
   }

/*
 *	Copy the required data into the output buffer "buf" and set "buflen"
 *	to the number of bytes in this buffer.
 */
   marshal_arp_pkt(buf, &frame_hdr, &arpei, &buflen, padding, padding_len);
/*
 *	If he is NULL, just return with the packet length.
 */
   if (he == NULL)
      return buflen;
/*
 *	Check that the host is live. Complain if not.
 */
   if (!he->live) {
      warn_msg("***\tsend_packet called on non-live host: SHOULDN'T HAPPEN");
      return 0;
   }
/*
 *	Update the last send times for this host.
 */
   Gettimeofday(last_packet_time);
   he->last_send_time.tv_sec  = last_packet_time->tv_sec;
   he->last_send_time.tv_usec = last_packet_time->tv_usec;
   he->num_sent++;
/*
 *	Send the packet.
 */
   if (verbose > 1)
      warn_msg("---\tSending packet #%u to host %s tmo %d", he->num_sent,
               my_ntoa(he->addr), he->timeout);
   if (write_pkt_to_file) {
      nsent = write(write_pkt_to_file, buf, buflen);
   } else if (!pkt_read_file_flag) {
      nsent = pcap_sendpacket(pcap_handle, buf, buflen);
   }
   if (nsent < 0)
      err_sys("ERROR: failed to send packet");

   return buflen;
}

/*
 *      clean_up -- Protocol-specific Clean-Up routine.
 *
 *      Inputs:
 *
 *      None.
 *
 *      Returns:
 *
 *      None.
 *
 *      This is called once after all hosts have been processed. It can be
 *      used to perform any tidying-up or statistics-displaying required.
 *      It does not have to do anything.
 */
void
clean_up(pcap_t *pcap_handle) {
   struct pcap_stat stats;

   if (!plain_flag) {
      if (pcap_handle && !pkt_read_file_flag) {
         if ((pcap_stats(pcap_handle, &stats)) < 0)
            err_msg("pcap_stats: %s", pcap_geterr(pcap_handle));

         printf("%u packets Recibido by filter, %u packets dropped by kernel\n",
                stats.ps_recv, stats.ps_drop);
      }
   }
   if (pcap_dump_handle) {
      pcap_dump_close(pcap_dump_handle);
   }
   if (pcap_handle) {
      pcap_close(pcap_handle);
   }
}

/*
 *	usage -- display usage message and exit
 *
 *	Inputs:
 *
 *	status		Status code to pass to exit()
 *	detailed	zero for brief output, non-zero for detailed output
 *
 *	Returns:
 *
 *	None (this function never returns).
 */
void
usage(int status, int detailed) {
   fprintf(stdout, "Usar: arp-scan [opciones] [hosts...]\n");
   fprintf(stdout, "\n");
   fprintf(stdout, "El objetivo hosts debe ser especificado en la línea de comandos salvo la opción --file\n");
   fprintf(stdout, "en este caso, los objetivos son leidos desde un archivo, o ");
   fprintf(stdout, "la opción --localnet que buscara\n los objetivos de nuestra red local, creadas a partir de nuestra ip y máscara\n");
   fprintf(stdout, "\n");
   fprintf(stdout, "Necesitas ser root, o arp-scan debe tener el SUID 0 para funcionar\n");
   fprintf(stdout, "\n");
   fprintf(stdout, "Los objetivos deben ser especificados como una dirección IP o como nombres de equipo(hostnames). También se puede\n");
   fprintf(stdout, "especificar el objetivo como IP de red/bits (ejem. 192.168.1.0/24) para especificar todos los hosts de una red.\n");
   fprintf(stdout, "La máscara de red y broadcast también son objetivos en este caso.\n");
   fprintf(stdout, "IPorigen-IPfin (ejem. 192.168.1.3-192.168.1.27) especifica un rango de red.\n");
   fprintf(stdout, "\n");
   if (detailed) {
      fprintf(stdout, "Opciones:\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "Nota: cuando una opción necesita un valor, este valor es especificado como una letra entre símbolos mayor-menor. La letra indica el tipo de valor.");
      fprintf(stdout, "\n");
      fprintf(stdout, "<s> Una <s> indica una cadena o string, ejem. --file=hostlist.txt.\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<i> Un entero.  Puede ser especificado en hexadecima si va precedido de 0x.\n");
      fprintf(stdout, "    ejem. --arppro=2048 or --arpro=0x0800.\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<f> Un numero flotante, ejem. --backoff=1.5.\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<m> Una dirección Ethernet MAC.  Puede ser espacificado en formato\n");
      fprintf(stdout, "    01:23:45:67:89:ab, o como 01-23-45-67-89-ab. Los caracteres alfanuméricos pueden estar en mayúsculas o minúsculas\n");
      fprintf(stdout, "    may be either upper or lower case. E.g. --arpsha=01:23:45:67:89:ab.\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<a> Una dirección IPv4, ejem. --arpspa=10.0.0.1\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<h> Los datos binarios especificados como una cadena hexadecimal, no deben\n");
      fprintf(stdout, "    incluir un prefijo 0x. Los datos de relleno se pueden poner el mayusculas o minusculas\n");
      fprintf(stdout, "    ejemp. --padding=aaaaaaaaaaaa\n");
      fprintf(stdout, "\n");
      fprintf(stdout, "<x> Something else. See the description of the option for details.\n");
      fprintf(stdout, "\n--help o -h\t\tMuestra esta pantalla de ayuda y sale.\n");
      fprintf(stdout, "\n--file=<s> o -f <s>\tLee hostnames o direcciones ip desde un archivo\n");
      fprintf(stdout, "\t\t\to desde la entrada stdin, usando \"-\" de la forma --file\"-\".\n");
      fprintf(stdout, "\n--localnet o -l\tGenera las direcciones de red en funcion de la ip de nuetra interfaz.\n");
      fprintf(stdout, "\t\t\tSi usas esta opcion, no puedes usar --file\n");
      fprintf(stdout, "\n--retry=<i> o -r <i>\tPone el numeros de intentos por host a <i>,\n");
      fprintf(stdout, "\t\t\tdefault=%d.\n", DEFAULT_RETRY);
      fprintf(stdout, "\n--timeout=<i> o -t <i>\tInicia el timeout por equipo a <i> ms, default=%d.\n", DEFAULT_TIMEOUT);
      fprintf(stdout, "\n--interval=<x> o -i <x> Pone el minimo intervalo de paquetes a <x>.\n");
      fprintf(stdout, "\n--bandwidth=<x> o -B <x> Establezca el ancho de banda de salida deseado para <x>, default=%d.\n", DEFAULT_BANDWIDTH);
      fprintf(stdout, "\n--backoff=<f> o -b <f>\tEstablece el timeout backoff factor a <f>, default=%.2f.\n", DEFAULT_BACKOFF_FACTOR);
      fprintf(stdout, "\n--verbose o -v\t\tMuestra los mensajes en modo verbose. Hay tres modos 1,2,3\n");
      fprintf(stdout, "\n--version o -V\t\tMuestra la version del programa y sale.\n");
      fprintf(stdout, "\n--random o -R\t\tAleatoriza la lista de host.\n");
      fprintf(stdout, "\n--randomseed=<i>\tUsa <i> Para sembrar el generador de números pseudo aleatorios.\n");
      fprintf(stdout, "\n--numeric o -N\t\tSolo direcciones IP, no aceptamos hostnames.\n");
      fprintf(stdout, "\n--snap=<i> o -n <i>\tEstablezca el tamaño de pcap snap a <i>. Default=%d.\n", SNAPLEN);
      fprintf(stdout, "\n--interface=<s> o -I <s> Establezca la interfaz de red <s>.\n");
      fprintf(stdout, "\n--quiet o -q\t\tSolo muestra la minima informacion.\n");
      fprintf(stdout, "\n--plain o -x\t\tMuestra solo las respuestas de hosts.\n");
      fprintf(stdout, "\n--ignoredups o -g\tNo muestra paquetes duplicados.\n");
      fprintf(stdout, "\n--ouifile=<s> o -O <s>\tUsa IEEE Ethernet OUI para mapear el vendedor <s>.\n");
      fprintf(stdout, "\n--iabfile=<s> o -O <s>\tUsa IEEE Ethernet IAB para mapear el vendedor <s>.\n");
      fprintf(stdout, "\n--macfile=<s> o -O <s>\tUsa la Ethernet MAC para mapear el vendedor <s>.\n");
      fprintf(stdout, "\n--srcaddr=<m> o -S <m> Pone el origen de Ethernet MAC a <m>.\n");
      fprintf(stdout, "\n--destaddr=<m> o -T <m> Manda el paquete a Ethernet MAC address <m>\n");
      fprintf(stdout, "\n--arpsha=<m> o -u <m>\tUsa <m> como el ARP source Ethernet address\n");
      fprintf(stdout, "\n--arptha=<m> o -w <m>\tUsa <m> como the ARP target Ethernet address\n");
      fprintf(stdout, "\n--prototype=<i> o -y <i> Pone el tipo de protocolo de Ethernet <i>, default=0x%.4x.\n", DEFAULT_ETH_PRO);
      fprintf(stdout, "\n--arphrd=<i> o -H <i>\tPone <i> para la direccion de hardware ARP, default=%d.\n", DEFAULT_ARP_HRD);
      fprintf(stdout, "\n--arppro=<i> o -p <i>\tUsa <i> para el tipo de protocolo ARP, default=0x%.4x.\n", DEFAULT_ARP_PRO);
      fprintf(stdout, "\n--arphln=<i> o -a <i>\tPone el tamaño de la direccion de hardware a <i>, default=%d.\n", DEFAULT_ARP_HLN);
      fprintf(stdout, "\n--arppln=<i> o -P <i>\tPone la direccion del protocolo <i>, default=%d.\n", DEFAULT_ARP_PLN);
      fprintf(stdout, "\n--arpop=<i> o -o <i>\tUsa <i> como operacion para ARP, default=%d.\n", DEFAULT_ARP_OP);
      fprintf(stdout, "\n--arpspa=<a> o -s <a>\tUsa <a> como la direccion de origen IP.\n");
      fprintf(stdout, "\n--padding= o -A \tEspecifica padding after packet data.\n");
      fprintf(stdout, "\n--grx=<i> o -G <i>\tUsamos <i> como ultimo octeto de la ip origen.\n");
      fprintf(stdout, "\n--llc or -L\t\tUse RFC 1042 LLC framing with SNAP.\n");
      fprintf(stdout, "\n--vlan=<i> or -Q <i>\tUsa 802.1Q etiquetado con VLAN id <i>.\n");
      fprintf(stdout, "\n--pcapsavefile=<s> or -W <s>\tGuarda los paquetes recibidos a un archivo <s>.\n");
      fprintf(stdout, "\n--rtt or -D\t\tMuestra el tiempo de viaje del paquete.\n");
   } else {
      fprintf(stdout, "usa \"arp-scan --help\" para mostrar informacion sobre las opciones.\n");
   }
   fprintf(stdout, "\n");
   fprintf(stdout, "Mande cualquier problema o sugerencia a %s\n", PACKAGE_BUGREPORT);
   fprintf(stdout, "Vea la web https://incidencias.dipgra.es/arp-scan\n");
   exit(status);
}

/*
 *      add_host_pattern -- Add one or more new host to the list.
 *
 *      Inputs:
 *
 *      pattern = The host pattern to add.
 *      host_timeout = Per-host timeout in ms.
 *
 *      Returns: None
 *
 *      This adds one or more new hosts to the list. The pattern argument
 *      can either be a single host or IP address, in which case one host
 *      will be added to the list, or it can specify a number of hosts with
 *      the IPnet/bits or IPstart-IPend formats.
 *
 *      The host_timeout and num_hosts arguments are passed unchanged to
 *	add_host().
 */
void
add_host_pattern(const char *pattern, unsigned host_timeout) {
   char *patcopy;
   struct in_addr in_val;
   struct in_addr mask_val;
   unsigned numbits;
   char *cp;
   uint32_t ipnet_val;
   uint32_t network;
   uint32_t mask;
   unsigned long hoststart;
   unsigned long hostend;
   unsigned i;
   uint32_t x;
   static int first_call=1;
   static regex_t iprange_pat;
   static regex_t ipslash_pat;
   static regex_t ipmask_pat;
   static const char *iprange_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
   static const char *ipslash_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+";
   static const char *ipmask_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
/*
 *	Compile regex patterns if this is the first time we've been called.
 */
   if (first_call) {
      int result;

      first_call = 0;
      if ((result=regcomp(&iprange_pat, iprange_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &iprange_pat, errbuf, MAXLINE);
         err_msg("ERROR: no puedo compilar el patron regex \"%s\": %s",
                 iprange_pat_str, errbuf);
      }
      if ((result=regcomp(&ipslash_pat, ipslash_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &ipslash_pat, errbuf, MAXLINE);
         err_msg("ERROR: no puedo compilar el patron regex \"%s\": %s",
                 ipslash_pat_str, errbuf);
      }
      if ((result=regcomp(&ipmask_pat, ipmask_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &ipmask_pat, errbuf, MAXLINE);
         err_msg("ERROR: no puedo compilar el patron regex \"%s\": %s",
                 ipmask_pat_str, errbuf);
      }
   }
/*
 *	Make a copy of pattern because we don't want to modify our argument.
 */
   patcopy = dupstr(pattern);

   if (!(regexec(&ipslash_pat, patcopy, 0, NULL, 0))) { /* IPnet/bits */
/*
 *	Get IPnet and bits as integers. Perform basic error checking.
 */
      cp=strchr(patcopy, '/');
      *(cp++)='\0';	/* patcopy points to IPnet, cp points to bits */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s no es una IP valida", patcopy);
      ipnet_val=ntohl(in_val.s_addr);	/* We need host byte order */
      numbits=Strtoul(cp, 10);
      if (numbits<3 || numbits>32)
         err_msg("ERROR: Number of bits in %s must be between 3 and 32",
                 pattern);
/*
 *	Construct 32-bit network bitmask from number of bits.
 */
      mask=0;
      for (i=0; i<numbits; i++)
         mask += 1 << i;
      mask = mask << (32-i);
/*
 *	Mask off the network. Warn if the host bits were non-zero.
 */
      network=ipnet_val & mask;
      if (network != ipnet_val)
         warn_msg("WARNING: host part of %s is non-zero", pattern);
/*
 *	Determine maximum and minimum host values. We include the host
 *	and broadcast.
 */
      hoststart=0;
      hostend=(1<<(32-numbits))-1;
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         uint32_t hostip;
         int b1, b2, b3, b4;
         char ipstr[16];

         hostip = network+i;
         b1 = (hostip & 0xff000000) >> 24;
         b2 = (hostip & 0x00ff0000) >> 16;
         b3 = (hostip & 0x0000ff00) >> 8;
         b4 = (hostip & 0x000000ff);
         snprintf(ipstr, sizeof(ipstr), "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, host_timeout, 1);
      }
   } else if (!(regexec(&ipmask_pat, patcopy, 0, NULL, 0))) { /* IPnet:netmask */
/*
 *	Get IPnet and bits as integers. Perform basic error checking.
 */
      cp=strchr(patcopy, ':');
      *(cp++)='\0';	/* patcopy points to IPnet, cp points to netmask */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      ipnet_val=ntohl(in_val.s_addr);	/* We need host byte order */
      if (!(inet_aton(cp, &mask_val)))
         err_msg("ERROR: %s is not a valid netmask", patcopy);
      mask=ntohl(mask_val.s_addr);	/* We need host byte order */
/*
 *	Calculate the number of bits in the network.
 */
      x = mask;
      for (numbits=0; x != 0; x>>=1) {
         if (x & 0x01) {
            numbits++;
         }
      }
/*
 *	Mask off the network. Warn if the host bits were non-zero.
 */
      network=ipnet_val & mask;
      if (network != ipnet_val)
         warn_msg("WARNING: host part of %s is non-zero", pattern);
/*
 *	Determine maximum and minimum host values. We include the host
 *	and broadcast.
 */
      hoststart=0;
      hostend=(1<<(32-numbits))-1;
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         uint32_t hostip;
         int b1, b2, b3, b4;
         char ipstr[16];

         hostip = network+i;
         b1 = (hostip & 0xff000000) >> 24;
         b2 = (hostip & 0x00ff0000) >> 16;
         b3 = (hostip & 0x0000ff00) >> 8;
         b4 = (hostip & 0x000000ff);
         snprintf(ipstr, sizeof(ipstr), "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, host_timeout, 1);
      }
   } else if (!(regexec(&iprange_pat, patcopy, 0, NULL, 0))) { /* IPstart-IPend */
/*
 *	Get IPstart and IPend as integers.
 */
      cp=strchr(patcopy, '-');
      *(cp++)='\0';	/* patcopy points to IPstart, cp points to IPend */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      hoststart=ntohl(in_val.s_addr);	/* We need host byte order */
      if (!(inet_aton(cp, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", cp);
      hostend=ntohl(in_val.s_addr);	/* We need host byte order */
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         int b1, b2, b3, b4;
         char ipstr[16];

         b1 = (i & 0xff000000) >> 24;
         b2 = (i & 0x00ff0000) >> 16;
         b3 = (i & 0x0000ff00) >> 8;
         b4 = (i & 0x000000ff);
         snprintf(ipstr, sizeof(ipstr), "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, host_timeout, 1);
      }
   } else {	/* Single host or IP address */
      add_host(patcopy, host_timeout, numeric_flag);
   }
   free(patcopy);
}

/*
 *	add_host -- Add a new host to the list.
 *
 *	Inputs:
 *
 *	host_name = The Name or IP address of the host.
 *	host_timeout = The initial host timeout in ms.
 *	numeric_only = 1 if the host name is definitely an IP address in
 *	               dotted quad format, or 0 if it may be a hostname or
 *	               IP address.
 *
 *	Returns:
 *
 *	None.
 *
 *	This function is called before the helistptr array is created, so
 *	we use the helist array directly.
 */
void
add_host(const char *host_name, unsigned host_timeout, int numeric_only) {
   struct in_addr *hp=NULL;
   struct in_addr addr;
   host_entry *he;
   static int num_left=0;	/* Number of free entries left */
   int result;
   char *ga_err_msg;

   if (numeric_only) {
      result = inet_pton(AF_INET, host_name, &addr);
      if (result < 0) {
         err_sys("ERROR: inet_pton failed for %s", host_name);
      } else if (result == 0) {
         warn_msg("WARNING: \"%s\" is not a valid IPv4 address - target ignored", host_name);
         return;
      }
   } else {
      hp = get_host_address(host_name, AF_INET, &addr, &ga_err_msg);
      if (hp == NULL) {
         warn_msg("WARNING: get_host_address failed for \"%s\": %s - target ignored",
                  host_name, ga_err_msg);
         return;
      }
   }

   if (!num_left) {	/* No entries left, allocate some more */
      if (helist)
         helist=Realloc(helist, (num_hosts * sizeof(host_entry)) +
                        REALLOC_COUNT*sizeof(host_entry));
      else
         helist=Malloc(REALLOC_COUNT*sizeof(host_entry));
      num_left = REALLOC_COUNT;
   }

   he = helist + num_hosts;	/* Would array notation be better? */
   num_hosts++;
   num_left--;

   memcpy(&(he->addr), &addr, sizeof(struct in_addr));
   he->live = 1;
   he->timeout = host_timeout * 1000;	/* Convert from ms to us */
   he->num_sent = 0;
   he->num_recv = 0;
   he->last_send_time.tv_sec=0;
   he->last_send_time.tv_usec=0;
}

/*
 * 	remove_host -- Remove the specified host from the list
 *
 *	inputs:
 *
 *	he = Puntero to host entry to remove.
 *
 *	Returns:
 *
 *	None.
 *
 *	If the host being removed is the one pointed to by the cursor, this
 *	function updates cursor so that it points to the next entry.
 */
void
remove_host(host_entry **he) {
   if ((*he)->live) {
      (*he)->live = 0;
      live_count--;
      if (*he == *cursor)
         advance_cursor();
   } else {
      if (verbose > 1)
         warn_msg("***\tremove_host called on non-live host: SHOULDN'T HAPPEN");
   }
}

/*
 *	advance_cursor -- Advance the cursor to point at next live entry
 *
 *	Inputs:
 *
 *	None.
 *
 *	Returns:
 *
 *	None.
 *
 *	Does nothing if there are no live entries in the list.
 */
void
advance_cursor(void) {
   if (live_count) {
      do {
         if (cursor == (helistptr+(num_hosts-1)))
            cursor = helistptr;	/* Wrap round to beginning */
         else
            cursor++;
      } while (!(*cursor)->live);
   } /* End If */
}

/*
 *	find_host	-- Find a host in the list
 *
 *	Inputs:
 *
 *	he 	Puntero to the current position in the list. Search runs
 *		backwards starting from this point.
 *	addr 	The source IP address that the packet came from.
 *
 *	Returns a Puntero to the host entry associated with the specified IP
 *	or NULL if no match found.
 *
 *	This routine finds the host by IP address by comparing "addr" against
 *	"he->addr" for each entry in the list.
 */
host_entry *
find_host(host_entry **he, struct in_addr *addr) {
   host_entry **p;
   int found = 0;
   unsigned iterations = 0;	/* Used for debugging */
/*
 *      Don't try to match if host ptr is NULL.
 *      This should never happen, but we check just in case.
 */
   if (*he == NULL) {
      return NULL;
   }
/*
 *	Try to match against out host list.
 */
   p = he;

   do {
      iterations++;
      if ((*p)->addr.s_addr == addr->s_addr) {
         found = 1;
      } else {
         if (p == helistptr) {
            p = helistptr + (num_hosts-1);	/* Wrap round to end */
         } else {
            p--;
         }
      }
   } while (!found && p != he);


   if (found)
      return *p;
   else
      return NULL;
}

/*
 *	recvfrom_wto -- Receive packet with timeout
 *
 *	Inputs:
 *
 *	sock_fd		= Socket file descriptor.
 *	tmo		= Select timeout in us.
 *	pcap_handle 	= pcap handle
 *
 *	Returns:
 *
 *	None.
 *
 *	If the socket file descriptor is -1, this indicates that we are
 *	reading packets from a pcap file and there is no associated network
 *	device.
 */
void
recvfrom_wto(int sock_fd, int tmo, pcap_t *pcap_handle) {
   fd_set readset;
   struct timeval to;
   int n;

   FD_ZERO(&readset);
   if (sock_fd >= 0)
      FD_SET(sock_fd, &readset);
   to.tv_sec  = tmo/1000000;
   to.tv_usec = (tmo - 1000000*to.tv_sec);
   n = select(sock_fd+1, &readset, NULL, NULL, &to);
   if (n < 0) {
      err_sys("select");
   } else if (n == 0 && sock_fd >= 0) {
/*
 * For the BPF pcap implementation, we call pcap_dispatch() even if select
 * times out. This is because on many BPF implementations, select() doesn't
 * indicate if there is input waiting on a BPF device.
 */
#ifdef ARP_PCAP_BPF
      if ((pcap_dispatch(pcap_handle, -1, callback, NULL)) == -1)
         err_sys("pcap_dispatch: %s\n", pcap_geterr(pcap_handle));
#endif
      return;	/* Timeout */
   }
/*
 * Call pcap_dispatch() to process the packet if we are reading packets.
 */
   if (pcap_handle) {
      if ((pcap_dispatch(pcap_handle, -1, callback, NULL)) == -1)
         err_sys("pcap_dispatch: %s\n", pcap_geterr(pcap_handle));
   }
}

/*
 *	dump_list -- Display contents of host list for debugging
 *
 *	Inputs:
 *
 *	None.
 *
 *	Returns:
 *
 *	None.
 */
void
dump_list(void) {
   unsigned i;

   printf("Host List:\n\n");
   printf("Entry\tIP Address\n");
   for (i=0; i<num_hosts; i++)
      printf("%u\t%s\n", i+1, my_ntoa(helistptr[i]->addr));
   printf("\nTotal of %u host entries.\n\n", num_hosts);
}

/*
 * callback -- pcap callback function
 *
 * Inputs:
 *
 *	args		Special args (not used)
 *	header		pcap header structure
 *	packet_in	The captured packet
 *
 * Returns:
 *
 * None
 */
void
callback(u_char *args ATTRIBUTE_UNUSED,
         const struct pcap_pkthdr *header, const u_char *packet_in) {
   arp_ether_ipv4 arpei;
   ether_hdr frame_hdr;
   int n = header->caplen;
   struct in_addr source_ip;
   host_entry *temp_cursor;
   unsigned char extra_data[MAX_FRAME];
   size_t extra_data_len;
   int vlan_id;
   int framing;
/*
 *      Check that the packet is large enough to decode.
 */
   if (n < ETHER_HDR_SIZE + ARP_PKT_SIZE) {
      printf("%d byte packet too short to decode\n", n);
      return;
   }
/*
 *	Unmarshal packet buffer into structures and determine framing type
 */
   framing = unmarshal_arp_pkt(packet_in, n, &frame_hdr, &arpei, extra_data,
                               &extra_data_len, &vlan_id);
/*
 *	Determine source IP address.
 */
   source_ip.s_addr = arpei.ar_sip;
/*
 *	We've Recibido a response. Try to match up the packet by IP address
 *
 *	We should really start searching at the host before the cursor, as we
 *	know that the host to match cannot be the one at the cursor position
 *	because we call advance_cursor() after sending each packet. However,
 *	the time saved is minimal, and it's not worth the extra complexity.
 */
   temp_cursor=find_host(cursor, &source_ip);
   if (temp_cursor) {
/*
 *	We found an IP match for the packet.
 */
/*
 *	Display the packet and increment the number of responders if
 *	the entry is "live" or we are not ignoring duplicates.
 */
      temp_cursor->num_recv++;
      if (verbose > 1)
         warn_msg("---\tPaquete recibido #%u desde %s",
                  temp_cursor->num_recv ,my_ntoa(source_ip));
      if ((temp_cursor->live || !ignore_dups)) {
         if (pcap_dump_handle) {
            pcap_dump((unsigned char *)pcap_dump_handle, header, packet_in);
         }
         display_packet(temp_cursor, &arpei, extra_data, extra_data_len,
                        framing, vlan_id, &frame_hdr, header);
         responders++;
      }
      if (verbose > 1)
         warn_msg("---\tQuitando host %s - Recibido %d bytes",
                  my_ntoa(source_ip), n);
      remove_host(&temp_cursor);
   } else {
/*
 *	The Recibido packet is not from an IP address in the list
 *	Issue a message to that effect and ignore the packet.
 */
      if (verbose)
         warn_msg("---\tIgnorando %d bytes desde host desconocido %s", n, my_ntoa(source_ip));
   }
}

/*
 *	process_options	--	Process options and arguments.
 *
 *	Inputs:
 *
 *	argc	Command line arg count
 *	argv	Command line args
 *
 *	Returns:
 *
 *	None.
 */
void
process_options(int argc, char *argv[]) {
   struct option long_options[] = {
      {"file", required_argument, 0, 'f'},
      {"grx", required_argument, 0, 'G'},
      {"help", no_argument, 0, 'h'},
      {"retry", required_argument, 0, 'r'},
      {"timeout", required_argument, 0, 't'},
      {"interval", required_argument, 0, 'i'},
      {"backoff", required_argument, 0, 'b'},
      {"verbose", no_argument, 0, 'v'},
      {"version", no_argument, 0, 'V'},
      {"snap", required_argument, 0, 'n'},
      {"interface", required_argument, 0, 'I'},
      {"quiet", no_argument, 0, 'q'},
      {"ignoredups", no_argument, 0, 'g'},
      {"random", no_argument, 0, 'R'},
      {"numeric", no_argument, 0, 'N'},
      {"bandwidth", required_argument, 0, 'B'},
      {"ouifile", required_argument, 0, 'O'},
      {"iabfile", required_argument, 0, 'F'},
      {"macfile", required_argument, 0, 'm'},
      {"arpspa", required_argument, 0, 's'},
      {"arpop", required_argument, 0, 'o'},
      {"arphrd", required_argument, 0, 'H'},
      {"arppro", required_argument, 0, 'p'},
      {"destaddr", required_argument, 0, 'T'},
      {"arppln", required_argument, 0, 'P'},
      {"arphln", required_argument, 0, 'a'},
      {"padding", required_argument, 0, 'A'},
      {"prototype", required_argument, 0, 'y'},
      {"arpsha", required_argument, 0, 'u'},
      {"arptha", required_argument, 0, 'w'},
      {"srcaddr", required_argument, 0, 'S'},
      {"localnet", no_argument, 0, 'l'},
      {"llc", no_argument, 0, 'L'},
      {"vlan", required_argument, 0, 'Q'},
      {"pcapsavefile", required_argument, 0, 'W'},
      {"writepkttofile", required_argument, 0, OPT_WRITEPKTTOFILE},
      {"readpktfromfile", required_argument, 0, OPT_READPKTFROMFILE},
      {"rtt", no_argument, 0, 'D'},
      {"plain", no_argument, 0, 'x'},
      {"randomseed", required_argument, 0, OPT_RANDOMSEED},
      {0, 0, 0, 0}
   };
/*
 * available short option characters:
 *
 * lower:       --cde----jk--------------z
 * UPPER:       --C-E-G--JK-M-------U--XYZ
 * Digits:      0123456789
 */
   const char *short_options =
      "f:G:hr:t:i:b:vVn:I:qgRNB:O:s:o:H:p:T:P:a:A:y:u:w:S:F:m:lLQ:W:Dx";
   int arg;
   int options_index=0;

   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
         struct in_addr source_ip_address;
         int result;

         case 'f':	/* --file */
            strlcpy(filename, optarg, sizeof(filename));
            filename_flag=1;
            break;
         case 'G':	/* --grx */
	    octeto=Strtol(optarg, 0);
            grx_flag=1;
            break;
         case 'h':	/* --help */
            usage(EXIT_SUCCESS, 1);
            break;	/* NOTREACHED */
         case 'r':	/* --retry */
            retry=Strtoul(optarg, 10);
            break;
         case 't':	/* --timeout */
            timeout=Strtoul(optarg, 10);
            break;
         case 'i':	/* --interval */
            interval=str_to_interval(optarg);
            break;
         case 'b':	/* --backoff */
            backoff_factor=atof(optarg);
            break;
         case 'v':	/* --verbose */
            verbose++;
            break;
         case 'V':	/* --version */
            arp_scan_version();
            exit(0);
            break;	/* NOTREACHED */
         case 'n':	/* --snap */
            snaplen=Strtol(optarg, 0);
            break;
         case 'I':	/* --interface */
            if_name = make_message("%s", optarg);
            break;
         case 'q':	/* --quiet */
            quiet_flag=1;
            break;
         case 'g':	/* --ignoredups */
            ignore_dups=1;
            break;
         case 'R':	/* --random */
            random_flag=1;
            break;
         case 'N':	/* --numeric */
            numeric_flag=1;
            break;
         case 'B':      /* --bandwidth */
            bandwidth=str_to_bandwidth(optarg);
            break;
         case 'O':	/* --ouifile */
            strlcpy(ouifilename, optarg, sizeof(ouifilename));
            break;
         case 'F':	/* --iabfile */
            strlcpy(iabfilename, optarg, sizeof(iabfilename));
            break;
         case 'm':	/* --macfile */
            strlcpy(macfilename, optarg, sizeof(macfilename));
            break;
         case 's':	/* --arpspa */
            arp_spa_flag = 1;
            if ((strcmp(optarg,"dest")) == 0) {
               arp_spa_is_tpa = 1;
            } else {
               if ((inet_pton(AF_INET, optarg, &source_ip_address)) <= 0)
                  err_sys("inet_pton failed for %s", optarg);
               memcpy(&arp_spa, &(source_ip_address.s_addr), sizeof(arp_spa));
            }
            break;
         case 'o':	/* --arpop */
            arp_op=Strtol(optarg, 0);
            break;
         case 'H':	/* --arphrd */
            arp_hrd=Strtol(optarg, 0);
            break;
         case 'p':	/* --arppro */
            arp_pro=Strtol(optarg, 0);
            break;
         case 'T':	/* --destaddr */
            result = get_ether_addr(optarg, target_mac);
            if (result != 0)
               err_msg("Invalid target MAC address: %s", optarg);
            break;
         case 'P':	/* --arppln */
            arp_pln=Strtol(optarg, 0);
            break;
         case 'a':	/* --arphln */
            arp_hln=Strtol(optarg, 0);
            break;
         case 'A':	/* --padding */
            if (strlen(optarg) % 2)     /* Length is odd */
               err_msg("ERROR: Length of --padding argument must be even (multiple of 2).");
            padding=hex2data(optarg, &padding_len);
            break;
         case 'y':	/* --prototype */
            eth_pro=Strtol(optarg, 0);
            break;
         case 'u':	/* --arpsha */
            result = get_ether_addr(optarg, arp_sha);
            if (result != 0)
               err_msg("Invalid source MAC address: %s", optarg);
            arp_sha_flag = 1;
            break;
         case 'w':	/* --arptha */
            result = get_ether_addr(optarg, arp_tha);
            if (result != 0)
               err_msg("Invalid target MAC address: %s", optarg);
            break;
         case 'S':	/* --srcaddr */
            result = get_ether_addr(optarg, source_mac);
            if (result != 0)
               err_msg("Invalid target MAC address: %s", optarg);
            source_mac_flag = 1;
            break;
         case 'l':	/* --localnet */
            localnet_flag = 1;
            break;
         case 'L':	/* --llc */
            llc_flag = 1;
            break;
         case 'Q':	/* --vlan */
            ieee_8021q_vlan = Strtol(optarg, 0);
            break;
         case 'W':	/* --pcapsavefile */
            strlcpy(pcap_savefile, optarg, sizeof(pcap_savefile));
            break;
         case OPT_WRITEPKTTOFILE: /* --writepkttofile */
            strlcpy(pkt_filename, optarg, sizeof(pkt_filename));
            pkt_write_file_flag=1;
            break;
         case OPT_READPKTFROMFILE: /* --readpktfromfile */
            strlcpy(pkt_filename, optarg, sizeof(pkt_filename));
            pkt_read_file_flag=1;
            break;
         case 'D':	/* --rtt */
            rtt_flag = 1;
            break;
         case 'x':	/* --plain */
            plain_flag = 1;
            break;
         case OPT_RANDOMSEED: /* --randomseed */
            random_seed=Strtoul(optarg, 0);
            break;
         default:	/* Unknown option */
            usage(EXIT_FAILURE, 0);
            break;	/* NOTREACHED */
      }
   }
}

/*
 *	arp_scan_version -- display version information
 *
 *	Inputs:
 *
 *	None.
 *
 *	Returns:
 *
 *	None.
 *
 *	This displays the arp-scan version information.
 */
void
arp_scan_version (void) {
   fprintf(stdout, "%s\n\n", PACKAGE_STRING);
   fprintf(stdout, "Copyright (C) 2005-2016 Roy Hills, NTA Monitor Ltd.\n");
   fprintf(stdout, "Modificado por Alberto Avidad Fernandez.OSL Diputación de Granada\n");
   fprintf(stdout, "Se puede redistribuir copias de arp-scan bajo los terminos de la licencia GNU\n");
   fprintf(stdout, "General Public License.\n");
   fprintf(stdout, "Para más información lea el fichero COPYING.\n");
   fprintf(stdout, "\n");
   fprintf(stdout, "%s\n", pcap_lib_version());
}

/*
 *	get_host_address -- Obtain target host IP address
 *
 *	Inputs:
 *
 *	name		The name to lookup
 *	af		The address family
 *	addr		Puntero to the IP address buffer
 *	error_msg	The error message, or NULL if no problem.
 *
 *	Returns:
 *
 *	Puntero to the IP address, or NULL if an error occurred.
 *
 *	This function is basically a wrapper for getaddrinfo().
 */
struct in_addr *
get_host_address(const char *name, int af, struct in_addr *addr,
                 char **error_msg) {
   static char err[MAXLINE];
   static struct in_addr ipa;

   struct addrinfo *res;
   struct addrinfo hints;
   struct sockaddr_in sa_in;
   int result;

   if (addr == NULL)	/* Use static storage if no buffer specified */
      addr = &ipa;

   memset(&hints, '\0', sizeof(hints));
   if (af == AF_INET) {
      hints.ai_family = AF_INET;
   } else {
      err_msg("get_host_address: unknown address family: %d", af);
   }

   result = getaddrinfo(name, NULL, &hints, &res);
   if (result != 0) {	/* Error occurred */
      snprintf(err, MAXLINE, "%s", gai_strerror(result));
      *error_msg = err;
      return NULL;
   }

   memcpy(&sa_in, res->ai_addr, sizeof(sa_in));
   memcpy(addr, &sa_in.sin_addr, sizeof(struct in_addr));

   freeaddrinfo(res);

   *error_msg = NULL;
   return addr;
}

/*
 *	my_ntoa -- IPv6 compatible inet_ntoa replacement
 *
 *	Inputs:
 *
 *	addr	The IP address
 *
 *	Returns:
 *
 *	Puntero to the string representation of the IP address.
 *
 *	This currently only supports IPv4.
 */
const char *
my_ntoa(struct in_addr addr) {
   static char ip_str[MAXLINE];
   const char *cp;

   cp = inet_ntop(AF_INET, &addr, ip_str, MAXLINE);

   return cp;
}

/*
 *	marshal_arp_pkt -- Marshal ARP packet from struct to buffer
 *
 *	Inputs:
 *
 *	buffer		Puntero to the output buffer
 *	frame_hdr	The Ethernet frame header
 *	arp_pkt		The ARP packet
 *	buf_siz		The size of the output buffer
 *	frame_padding	Any padding to add after the ARP payload.
 *	frame_padding_len	The length of the padding.
 *
 *	Returns:
 *
 *	None
 */
void
marshal_arp_pkt(unsigned char *buffer, ether_hdr *frame_hdr,
                arp_ether_ipv4 *arp_pkt, size_t *buf_siz,
                const unsigned char *frame_padding, size_t frame_padding_len) {
   unsigned char llc_snap[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00};
   unsigned char vlan_tag[] = {0x81, 0x00, 0x00, 0x00};
   unsigned char *cp;
   size_t packet_size;

   cp = buffer;
/*
 *	Set initial packet length to the size of an Ethernet frame using
 *	Ethernet-II format plus the size of the ARP data. This may be
 *	increased later by LLC/SNAP frame format or padding after the
 *	ARP data.
 */
   packet_size = sizeof(frame_hdr->dest_addr) + sizeof(frame_hdr->src_addr) +
                 sizeof(frame_hdr->frame_type) +
                 sizeof(arp_pkt->ar_hrd) + sizeof(arp_pkt->ar_pro) +
                 sizeof(arp_pkt->ar_hln) + sizeof(arp_pkt->ar_pln) +
                 sizeof(arp_pkt->ar_op)  + sizeof(arp_pkt->ar_sha) +
                 sizeof(arp_pkt->ar_sip) + sizeof(arp_pkt->ar_tha) +
                 sizeof(arp_pkt->ar_tip);
/*
 *	Copy the Ethernet frame header to the buffer.
 */
   memcpy(cp, &(frame_hdr->dest_addr), sizeof(frame_hdr->dest_addr));
   cp += sizeof(frame_hdr->dest_addr);
   memcpy(cp, &(frame_hdr->src_addr), sizeof(frame_hdr->src_addr));
   cp += sizeof(frame_hdr->src_addr);
/*
 *	Add 802.1Q tag if we are using VLAN tagging
 */
   if (ieee_8021q_vlan != -1) {
      uint16_t tci;

      tci = htons(ieee_8021q_vlan);
      memcpy(cp, vlan_tag, sizeof(vlan_tag));
      memcpy(cp+2, &tci, sizeof(tci));
      cp += sizeof(vlan_tag);
      packet_size += sizeof(vlan_tag);
   }
   if (llc_flag) {	/* With 802.2 LLC framing, type field is frame size */
      uint16_t frame_size;

      frame_size=htons(packet_size + sizeof(llc_snap));
      memcpy(cp, &(frame_size), sizeof(frame_size));
   } else {		/* Normal Ethernet-II framing */
      memcpy(cp, &(frame_hdr->frame_type), sizeof(frame_hdr->frame_type));
   }
   cp += sizeof(frame_hdr->frame_type);
/*
 *	Add IEEE 802.2 LLC and SNAP fields if we are using LLC frame format.
 */
   if (llc_flag) {
      memcpy(cp, llc_snap, sizeof(llc_snap));
      memcpy(cp+6, &(frame_hdr->frame_type), sizeof(frame_hdr->frame_type));
      cp += sizeof(llc_snap);
      packet_size += sizeof(llc_snap);
   }
/*
 *	Add the ARP data.
 */
   memcpy(cp, &(arp_pkt->ar_hrd), sizeof(arp_pkt->ar_hrd));
   cp += sizeof(arp_pkt->ar_hrd);
   memcpy(cp, &(arp_pkt->ar_pro), sizeof(arp_pkt->ar_pro));
   cp += sizeof(arp_pkt->ar_pro);
   memcpy(cp, &(arp_pkt->ar_hln), sizeof(arp_pkt->ar_hln));
   cp += sizeof(arp_pkt->ar_hln);
   memcpy(cp, &(arp_pkt->ar_pln), sizeof(arp_pkt->ar_pln));
   cp += sizeof(arp_pkt->ar_pln);
   memcpy(cp, &(arp_pkt->ar_op), sizeof(arp_pkt->ar_op));
   cp += sizeof(arp_pkt->ar_op);
   memcpy(cp, &(arp_pkt->ar_sha), sizeof(arp_pkt->ar_sha));
   cp += sizeof(arp_pkt->ar_sha);
   memcpy(cp, &(arp_pkt->ar_sip), sizeof(arp_pkt->ar_sip));
   cp += sizeof(arp_pkt->ar_sip);
   memcpy(cp, &(arp_pkt->ar_tha), sizeof(arp_pkt->ar_tha));
   cp += sizeof(arp_pkt->ar_tha);
   memcpy(cp, &(arp_pkt->ar_tip), sizeof(arp_pkt->ar_tip));
   cp += sizeof(arp_pkt->ar_tip);
/*
 *	Add padding if specified
 */
   if (frame_padding != NULL) {
      size_t safe_padding_len;

      safe_padding_len = frame_padding_len;
      if (packet_size + frame_padding_len > MAX_FRAME) {
         safe_padding_len = MAX_FRAME - packet_size;
      }
      memcpy(cp, frame_padding, safe_padding_len);
      cp += safe_padding_len;
      packet_size += safe_padding_len;
   }
   *buf_siz = packet_size;
}

/*
 *	unmarshal_arp_pkt -- Un paquete Marshall ARP de buffer a struct
 *
 *	Inputs:
 *
 *	buffer		Puntero al buffer de entrada
 *	buf_len		Tamaño del buffer de entrada
 *	frame_hdr	Cabecera de la trama ethernet
 *	arp_pkt		Los datos del paquete arp
 *	extra_data	Algun dato extra despues de los datos arp (normalmente relleno)
 *	extra_data_len	Tamaño de los datos extra
 *	vlan_id		802.1Q VLAN identificador
 *
 *	Devuelve:
 *
 *	Un entero que representa la estructura de enlace de datos:
 *	0 = Ethernet-II
 *	1 = 802.3 with LLC/SNAP
 *
 *      extra_data y extra_data_len solo se calculan y devuelven si
 *      extra_data no es NULL.
 *	vlan_id se establece en -1 si el paquete no utiliza el etiquetado 802.1Q.
 */
int
unmarshal_arp_pkt(const unsigned char *buffer, size_t buf_len,
                  ether_hdr *frame_hdr, arp_ether_ipv4 *arp_pkt,
                  unsigned char *extra_data, size_t *extra_data_len,
                  int *vlan_id) {
   const unsigned char *cp;
   int framing=FRAMING_ETHERNET_II;

   cp = buffer;
/*
 *	Extract the Ethernet frame header data
 */
   memcpy(&(frame_hdr->dest_addr), cp, sizeof(frame_hdr->dest_addr));
   cp += sizeof(frame_hdr->dest_addr);
   memcpy(&(frame_hdr->src_addr), cp, sizeof(frame_hdr->src_addr));
   cp += sizeof(frame_hdr->src_addr);
/*
 *	Check for 802.1Q VLAN tagging, indicated by a type code of
 *	0x8100 (TPID).
 */
   if (*cp == 0x81 && *(cp+1) == 0x00) {
      uint16_t tci;
      cp += 2;	/* Skip TPID */
      memcpy(&tci, cp, sizeof(tci));
      cp += 2;	/* Skip TCI */
      *vlan_id = ntohs(tci);
      *vlan_id &= 0x0fff;	/* Mask off PRI and CFI */
   } else {
      *vlan_id = -1;
   }
   memcpy(&(frame_hdr->frame_type), cp, sizeof(frame_hdr->frame_type));
   cp += sizeof(frame_hdr->frame_type);
/*
 *	Check for an LLC header with SNAP. If this is present, the 802.2 LLC
 *	header will contain DSAP=0xAA, SSAP=0xAA, Control=0x03.
 *	If this 802.2 LLC header is present, skip it and the SNAP header
 */
   if (*cp == 0xAA && *(cp+1) == 0xAA && *(cp+2) == 0x03) {
      cp += 8;	/* Skip eight bytes */
      framing = FRAMING_LLC_SNAP;
   }
/*
 *	Extract the ARP packet data
 */
   memcpy(&(arp_pkt->ar_hrd), cp, sizeof(arp_pkt->ar_hrd));
   cp += sizeof(arp_pkt->ar_hrd);
   memcpy(&(arp_pkt->ar_pro), cp, sizeof(arp_pkt->ar_pro));
   cp += sizeof(arp_pkt->ar_pro);
   memcpy(&(arp_pkt->ar_hln), cp, sizeof(arp_pkt->ar_hln));
   cp += sizeof(arp_pkt->ar_hln);
   memcpy(&(arp_pkt->ar_pln), cp, sizeof(arp_pkt->ar_pln));
   cp += sizeof(arp_pkt->ar_pln);
   memcpy(&(arp_pkt->ar_op), cp, sizeof(arp_pkt->ar_op));
   cp += sizeof(arp_pkt->ar_op);
   memcpy(&(arp_pkt->ar_sha), cp, sizeof(arp_pkt->ar_sha));
   cp += sizeof(arp_pkt->ar_sha);
   memcpy(&(arp_pkt->ar_sip), cp, sizeof(arp_pkt->ar_sip));
   cp += sizeof(arp_pkt->ar_sip);
   memcpy(&(arp_pkt->ar_tha), cp, sizeof(arp_pkt->ar_tha));
   cp += sizeof(arp_pkt->ar_tha);
   memcpy(&(arp_pkt->ar_tip), cp, sizeof(arp_pkt->ar_tip));
   cp += sizeof(arp_pkt->ar_tip);

   if (extra_data != NULL) {
      int length;

      length = buf_len - (cp - buffer);
      if (length > 0) {		/* Extra data after ARP packet */
         memcpy(extra_data, cp, length);
      }
      *extra_data_len = length;
   }

   return framing;
}

/*
 *	add_mac_vendor -- Add MAC/Vendor mappings to the hash table
 *
 *	Inputs:
 *
 *	map_filename	The name of the file containing the mappings
 *
 *	Returns:
 *
 *	The number of entries added to the hash table.
 */
int
add_mac_vendor(const char *map_filename) {
   static int first_call=1;
   FILE *fp;	/* MAC/Vendor file handle */
   static const char *oui_pat_str = "([^\t]+)\t[\t ]*([^\t\r\n]+)";
   static regex_t oui_pat;
   regmatch_t pmatch[3];
   size_t key_len;
   size_t data_len;
   char *key;
   char *data;
   char line[MAXLINE];
   int line_count;
   int result;
   ENTRY hash_entry;
/*
 *	Compile the regex pattern if this is the first time we
 *	have been called.
 */
   if (first_call) {
      first_call=0;
      if ((result=regcomp(&oui_pat, oui_pat_str, REG_EXTENDED))) {
         char reg_errbuf[MAXLINE];
         regerror(result, &oui_pat, reg_errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 oui_pat_str, reg_errbuf);
      }
   }
/*
 *	Open the file.
 */
   if ((fp = fopen(map_filename, "r")) == NULL) {
      warn_sys("WARNING: Cannot open MAC/Vendor file %s", map_filename);
      return 0;
   }
   line_count=0;
/*
 *
 */
   while (fgets(line, MAXLINE, fp)) {
      if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
         continue;	/* Skip blank lines and comments */
      result = regexec(&oui_pat, line, 3, pmatch, 0);
      if (result == REG_NOMATCH || pmatch[1].rm_so < 0 || pmatch[2].rm_so < 0) {
         warn_msg("WARNING: Could not parse oui: %s", line);
      } else if (result != 0) {
         char reg_errbuf[MAXLINE];
         regerror(result, &oui_pat, reg_errbuf, MAXLINE);
         err_msg("ERROR: oui regexec failed: %s", reg_errbuf);
      } else {
         key_len = pmatch[1].rm_eo - pmatch[1].rm_so;
         data_len = pmatch[2].rm_eo - pmatch[2].rm_so;
         key=Malloc(key_len+1);
         data=Malloc(data_len+1);
/*
 * We cannot use strlcpy because the source is not guaranteed to be null
 * terminated. Therefore we use strncpy, specifying one less that the total
 * length, and manually null terminate the destination.
 */
         strncpy(key, line+pmatch[1].rm_so, key_len);
         key[key_len] = '\0';
         strncpy(data, line+pmatch[2].rm_so, data_len);
         data[data_len] = '\0';
         hash_entry.key = key;
         hash_entry.data = data;
         if ((hsearch(hash_entry, ENTER)) == NULL) {
            warn_msg("hsearch([%s, %s], ENTER)", key, data);
         } else {
            line_count++;
         }
      }
   }
   fclose(fp);
   return line_count;
}

/*
 *	get_mac_vendor_filename -- Determine MAC/Vendor mapping filename
 *
 *	Inputs:
 *
 *	specified_filename	The filename specified on the command line
 *	default_datadir		The default data directory
 *	default_filename	The default filename
 *
 *	Returns:
 *
 *	The MAC/Vendor mapping filename.
 *
 *	If a filename was specified as an option on the command line, then
 *	that filename is used. Otherwise we look for the default filename
 *	in the current directory, and use that if it's present. Otherwise
 *	we use the default filename in the default directory.
 *
 */
char *
get_mac_vendor_filename(const char *specified_filename,
                        const char *default_datadir,
                        const char *default_filename) {
   struct stat statbuf;
   int status;
   char *file_name;

   if (*specified_filename == '\0') {	/* No filename specified */
      file_name = make_message("%s", default_filename);
      status = stat(file_name, &statbuf);
      if (status == -1 && errno == ENOENT) {
         free(file_name);
         file_name = make_message("%s/%s", default_datadir, default_filename);
      }
   } else {	/* Filename specified */
      file_name = make_message("%s", specified_filename);
   }
   return file_name;
}

/*
 *      get_source_ip   -- Get IP address associated with given interface
 *
 *      Inputs:
 *
 *      interface_name  The name of the network interface
 *      ip_addr         (output) The IP Address associated with the device
 *
 *      Returns:
 *
 *      Zero on success, or -1 on failure.
 */
int
get_source_ip(const char *interface_name, uint32_t *ip_addr) {
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *alldevsp;
   pcap_if_t *device;
   pcap_addr_t *addr;
   struct sockaddr *sa;
   struct sockaddr_in *sin = NULL;

   if ((pcap_findalldevs(&alldevsp, errbuf)) != 0) {
      printf("pcap_findalldevs: %s\n", errbuf);
   }

   device=alldevsp;
   while (device != NULL && (strcmp(device->name,interface_name) != 0)) {
      device=device->next;
   }
   if (device == NULL) {
      warn_msg("ERROR: Could not find interface: %s", interface_name);
      err_msg("ERROR: Check that the interface exists and is up");
   }

   for (addr=device->addresses; addr != NULL; addr=addr->next) {
      sa = addr->addr;
      if (sa->sa_family == AF_INET) {
         sin = (struct sockaddr_in *) sa;
         break;
      }
   }
   if (sin == NULL) {
      return -1;
   }

   memcpy(ip_addr, &(sin->sin_addr.s_addr), sizeof(*ip_addr));

   pcap_freealldevs(alldevsp);

   return 0;
}
