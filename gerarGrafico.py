import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np # Para CDF

# Define um estilo para os gráficos para melhor visualização
plt.style.use('seaborn-v0_8-whitegrid')

# Função auxiliar para criar um ID de conexão único para legendas e agrupamento
def create_conn_id_from_df(df_row):
    return f"{df_row['SrcIP']}:{df_row['SrcPort']}->{df_row['DstIP']}:{df_row['DstPort']}"

print("Iniciando a geração de gráficos...")

# --- 1. Curva da janela de congestionamento ao longo do tempo ---
# [cite: 8]
try:
    print("Processando cwnd_evolution.csv...")
    cwnd_df = pd.read_csv("cwnd_evolution.csv")
    if not cwnd_df.empty:
        cwnd_df['connection_id'] = cwnd_df.apply(create_conn_id_from_df, axis=1)
        
        # Normalizar o timestamp para iniciar em 0 para cada conexão
        # Adiciona uma coluna 'timestamp_relative_s' ao DataFrame
        # Esta operação agrupa por 'connection_id', e para cada grupo, subtrai o timestamp mínimo da coluna 'Timestamp_s'
        # Isso efetivamente "reinicia" o tempo para cada conexão, começando em 0.
        if 'Timestamp_s' in cwnd_df.columns:
            cwnd_df['timestamp_relative_s'] = cwnd_df.groupby('connection_id')['Timestamp_s'] \
                                                 .transform(lambda x: x - x.min())

            # Plotar para algumas conexões (ex: as 3 com mais amostras ou as primeiras)
            # Pega os IDs das conexões que têm mais entradas (amostras) no CSV
            top_connections_cwnd = cwnd_df['connection_id'].value_counts().nlargest(3).index
            
            if not top_connections_cwnd.empty:
                for conn_id in top_connections_cwnd:
                    plt.figure(figsize=(12, 6))
                    # Filtra os dados apenas para a conexão atual
                    data_to_plot = cwnd_df[cwnd_df['connection_id'] == conn_id]
                    # Cria o gráfico de linha: tempo relativo no eixo X, bytes em trânsito no eixo Y
                    plt.plot(data_to_plot['timestamp_relative_s'], data_to_plot['BytesInFlight'], marker='.', linestyle='-')
                    plt.title(f'Evolução da Janela de Congestionamento (Bytes em Trânsito)\n{conn_id}')
                    plt.xlabel('Tempo Relativo desde o Início do Fluxo (s)')
                    plt.ylabel('Bytes em Trânsito (Estimativa da CWND)')
                    plt.grid(True, which="both", ls="--", alpha=0.7) # Adiciona grade para melhor leitura
                    plt.tight_layout() # Ajusta o layout para evitar sobreposição
                    # Salva a figura. Os caracteres ':' e '>' são substituídos para evitar problemas com nomes de arquivos.
                    plt.savefig(f"cwnd_evolution_{conn_id.replace(':', '_').replace('->', '_')}.png")
                    plt.close()
                print("Gráficos da evolução da CWND gerados.")
            else:
                print("Não há conexões suficientes em cwnd_evolution.csv para plotar.")
        else:
            print("Coluna 'Timestamp_s' não encontrada em cwnd_evolution.csv.")
    else:
        print("cwnd_evolution.csv está vazio.")
except FileNotFoundError:
    print("Erro: cwnd_evolution.csv não encontrado.")
except pd.errors.EmptyDataError:
    print("Erro: cwnd_evolution.csv está vazio.")
except Exception as e:
    print(f"Erro ao processar cwnd_evolution.csv: {e}")

# --- 2. Gráfico de dispersão do RTT por conexão ---
# [cite: 9]
try:
    print("Processando rtt_samples.csv...")
    rtt_df = pd.read_csv("rtt_samples.csv")
    if not rtt_df.empty and 'RTT_ms' in rtt_df.columns:
        rtt_df['connection_id'] = rtt_df.apply(create_conn_id_from_df, axis=1)
        
        # Gráfico de Dispersão do RTT médio por conexão
        # Calcula o RTT médio para cada conexão única
        avg_rtt_df = rtt_df.groupby('connection_id')['RTT_ms'].mean().reset_index()
        # Remove RTTs <= 0 se existirem, pois não são válidos
        avg_rtt_df = avg_rtt_df[avg_rtt_df['RTT_ms'] > 0]

        if not avg_rtt_df.empty:
            plt.figure(figsize=(12, 8))
            if avg_rtt_df['connection_id'].nunique() > 20:
                avg_rtt_df['conn_idx'] = avg_rtt_df['connection_id'].astype('category').cat.codes
                y_values = avg_rtt_df['conn_idx']
                y_ticks_pos = avg_rtt_df['conn_idx'].unique()
                # Pega as categorias (nomes das conexões) e converte para uma lista de strings
                y_ticks_labels = avg_rtt_df.drop_duplicates(subset=['conn_idx']).sort_values('conn_idx')['connection_id'].astype(str).tolist() # <--- ALTERAÇÃO AQUI
                plt.yticks(ticks=y_ticks_pos, labels=y_ticks_labels, fontsize=8)
            else:
                y_values = avg_rtt_df['connection_id']
                plt.yticks(fontsize=8) # Se estiver usando os nomes diretamente, não precisa de 'labels' explícito aqui se y_values já for string


            # Cria o gráfico de dispersão
            plt.scatter(avg_rtt_df['RTT_ms'], y_values, alpha=0.7)
            plt.title('RTT Médio por Conexão (Dispersão)')
            plt.xlabel('RTT Médio (ms)')
            plt.ylabel('Conexão')
            plt.grid(True, which="both", ls="--", alpha=0.7)
            plt.tight_layout()
            plt.savefig("rtt_scatter_avg.png")
            plt.close()
            print("Gráfico de dispersão do RTT médio gerado.")

            # Boxplot para mostrar a distribuição de RTTs por conexão (se poucas conexões)
            # Só é útil se houver um número gerenciável de conexões únicas para exibir
            if rtt_df['connection_id'].nunique() <= 15 and rtt_df['connection_id'].nunique() > 0 :
                plt.figure(figsize=(12, max(8, rtt_df['connection_id'].nunique() * 0.6)))
                # Filtra RTTs <= 0 para o boxplot também
                rtt_plot_data = rtt_df[rtt_df['RTT_ms'] > 0]
                if not rtt_plot_data.empty:
                    sns.boxplot(data=rtt_plot_data, y='connection_id', x='RTT_ms', orient='h')
                    plt.title('Distribuição de RTT por Conexão')
                    plt.xlabel('RTT (ms)')
                    plt.ylabel('Conexão')
                    plt.grid(True, which="both", ls="--", alpha=0.7)
                    plt.tight_layout()
                    plt.savefig("rtt_boxplot.png")
                    plt.close()
                    print("Boxplot de RTTs gerado.")
                else:
                    print("Não há dados de RTT válidos (>0) para o boxplot.")
            else:
                print("Muitas conexões para um boxplot de RTTs detalhado ou nenhuma amostra de RTT válida.")
        else:
            print("Não há dados de RTT válidos (>0) para o gráfico de dispersão.")
    else:
        print("rtt_samples.csv está vazio ou não contém a coluna 'RTT_ms'.")
except FileNotFoundError:
    print("Erro: rtt_samples.csv não encontrado.")
except pd.errors.EmptyDataError:
    print("Erro: rtt_samples.csv está vazio.")
except Exception as e:
    print(f"Erro ao processar rtt_samples.csv: {e}")


# --- Carregar connection_summary.csv para os gráficos seguintes ---
summary_df = None
try:
    print("Processando connection_summary.csv...")
    summary_df = pd.read_csv("connection_summary.csv")
    if summary_df.empty:
        print("connection_summary.csv está vazio. Alguns gráficos não serão gerados.")
        summary_df = None 
    else:
        summary_df['connection_id'] = summary_df.apply(create_conn_id_from_df, axis=1)
except FileNotFoundError:
    print("Erro: connection_summary.csv não encontrado. Alguns gráficos não serão gerados.")
except pd.errors.EmptyDataError:
    print("Erro: connection_summary.csv está vazio.")
except Exception as e:
    print(f"Erro ao processar connection_summary.csv: {e}")


if summary_df is not None:
    # --- 3. CDF do tempo de estabelecimento das conexões (HandshakeTime_ms) ---
    # [cite: 9]
    if 'HandshakeTime_ms' in summary_df.columns:
        # Filtra valores não válidos (ex: -1.0 usado quando o handshake não foi completo) e NaNs
        handshake_times = summary_df['HandshakeTime_ms'][summary_df['HandshakeTime_ms'] >= 0].dropna()
        if not handshake_times.empty:
            plt.figure(figsize=(10, 6))
            # Passa a Série diretamente para o parâmetro x
            sns.ecdfplot(x=handshake_times, label="Handshake Time") # <--- ALTERAÇÃO AQUI
            plt.title('CDF do Tempo de Estabelecimento das Conexões (Handshake)')
            plt.xlabel('Tempo de Handshake (ms)')
            plt.ylabel('Frequência Cumulativa (CDF)')
            plt.grid(True, which="both", ls="--", alpha=0.7)
            plt.legend()
            plt.savefig("handshake_time_cdf.png")
            plt.close()
            print("Gráfico CDF do tempo de handshake gerado.")
        else:
            print("Não há dados de tempo de handshake válidos para plotar CDF.")
    else:
        print("Coluna 'HandshakeTime_ms' não encontrada em connection_summary.csv.")

    # --- 4. Histograma da taxa de retransmissões ---
    # (Retransmissions / TotalPackets)
    # [cite: 10]
    if 'Retransmissions' in summary_df.columns and 'TotalPackets' in summary_df.columns:
        # Evitar divisão por zero e calcular taxa apenas onde TotalPackets > 0
        valid_packets_df = summary_df[summary_df['TotalPackets'] > 0].copy()
        if not valid_packets_df.empty:
            # Calcula a taxa de retransmissão
            valid_packets_df.loc[:, 'RetransmissionRate'] = valid_packets_df['Retransmissions'] / valid_packets_df['TotalPackets']
            
            plt.figure(figsize=(10, 6))
            # Cria o histograma da taxa de retransmissão
            sns.histplot(data=valid_packets_df, x='RetransmissionRate', kde=False, bins=np.linspace(0,1,21)) # 20 bins entre 0 e 1
            plt.title('Histograma da Taxa de Retransmissões por Conexão')
            plt.xlabel('Taxa de Retransmissão (Retransmissões / Pacotes Totais)')
            plt.ylabel('Número de Conexões')
            plt.grid(True, axis='y', ls="--", alpha=0.7)
            plt.savefig("retransmission_rate_histogram.png")
            plt.close()
            print("Histograma da taxa de retransmissões gerado.")
        else:
            print("Não há conexões com TotalPackets > 0 para calcular taxa de retransmissão.")
    else:
        print("Colunas 'Retransmissions' ou 'TotalPackets' não encontradas em connection_summary.csv.")

    # --- 5. Comparação entre conexões curtas e longas ---
    # (Ex: Duration_s vs TotalBytes)
    # [cite: 10]
    if 'Duration_s' in summary_df.columns and 'TotalBytes' in summary_df.columns and 'IsElephant' in summary_df.columns:
        plt.figure(figsize=(12, 7))
        # Cria o gráfico de dispersão, colorindo os pontos pela flag 'IsElephant'
        # Filtra TotalBytes > 0 para escala logarítmica funcionar
        plot_df_comp = summary_df[summary_df['TotalBytes'] > 0].copy()
        if not plot_df_comp.empty:
            sns.scatterplot(data=plot_df_comp, x='Duration_s', y='TotalBytes', hue='IsElephant', alpha=0.6, s=50)
            plt.title('Comparação: Duração vs. Bytes Transferidos (Escala Log)')
            plt.xlabel('Duração da Conexão (s) - Escala Log')
            plt.ylabel('Total de Bytes Transferidos - Escala Log')
            plt.xscale('log') # Escala logarítmica ajuda a visualizar melhor dados com grande variação
            plt.yscale('log')
            plt.grid(True, which="both", ls="--", alpha=0.7)
            plt.legend(title='Fluxo Elefante (1=Sim, 0=Não)')
            plt.tight_layout()
            plt.savefig("connections_duration_vs_bytes.png")
            plt.close()
            print("Gráfico de comparação entre conexões gerado.")
        else:
            print("Não há conexões com TotalBytes > 0 para o gráfico de Duração vs Bytes.")
    else:
        print("Colunas 'Duration_s', 'TotalBytes' ou 'IsElephant' não encontradas em connection_summary.csv.")

# --- 6. Distribuição dos tamanhos dos segmentos ---
# [cite: 7] (Métrica obrigatória)
try:
    print("Processando segment_sizes.csv...")
    segments_df = pd.read_csv("segment_sizes.csv")
    if not segments_df.empty and 'SegmentSize' in segments_df.columns and 'Count' in segments_df.columns:
        # Para plotar a distribuição, podemos fazer um histograma ponderado pelo 'Count'
        # ou um barplot se o número de tamanhos únicos não for muito grande.
        
        # Criar uma lista expandida de tamanhos de segmento baseada na contagem
        expanded_sizes = []
        for _, row in segments_df.iterrows():
            expanded_sizes.extend([row['SegmentSize']] * row['Count'])
        
        if expanded_sizes:
            plt.figure(figsize=(12, 7))
            # Cria o histograma dos tamanhos de segmento
            # Define os bins para melhor visualização, especialmente se houver tamanhos muito grandes (MSS)
            # Pode ser necessário ajustar os bins com base nos seus dados
            max_size = pd.Series(expanded_sizes).max()
            bins = np.linspace(0, max_size if pd.notna(max_size) and max_size > 0 else 1500, 50) 
            sns.histplot(expanded_sizes, bins=bins, kde=False)
            plt.title('Distribuição dos Tamanhos dos Segmentos TCP (Header + Payload)')
            plt.xlabel('Tamanho do Segmento (bytes)')
            plt.ylabel('Frequência (Número de Segmentos)')
            plt.grid(True, axis='y', ls="--", alpha=0.7)
            # plt.xlim(0, 2000) # Pode ser útil limitar o eixo X se houver outliers
            plt.tight_layout()
            plt.savefig("segment_size_distribution.png")
            plt.close()
            print("Gráfico de distribuição de tamanhos de segmento gerado.")
        else:
            print("Não há dados de tamanho de segmento para plotar.")
    else:
        print("segment_sizes.csv está vazio ou não contém as colunas 'SegmentSize' ou 'Count'.")
except FileNotFoundError:
    print("Erro: segment_sizes.csv não encontrado.")
except pd.errors.EmptyDataError:
    print("Erro: segment_sizes.csv está vazio.")
except Exception as e:
    print(f"Erro ao processar segment_sizes.csv: {e}")

print("--- Geração de gráficos concluída ---")
