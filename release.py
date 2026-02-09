import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 설정 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v35.11", layout="wide")

st.markdown("""
    <style>
    .version-header { font-size: 24px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 15px; border-radius: 8px; border-left: 8px solid #1565C0; margin-bottom: 15px; }
    .report-box { padding: 20px; border: 1px solid #ddd; background-color: #ffffff; border-radius: 8px; margin-bottom: 25px; }
    .item-box { padding: 10px 14px; margin-bottom: 8px; border-left: 4px solid #90CAF9; background-color: #F5F5F5; font-size: 15px; line-height: 1.6; }
    .highlight { background-color: #FFF59D; color: black; font-weight: bold; padding: 2px 4px; border-radius: 4px; }
    .meta-label { color: #1565C0; font-weight: bold; font-size: 16px; border-bottom: 2px solid #BBDEFB; margin-bottom: 10px; display: inline-block; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [통합 엔진] 멀티 전략 파싱 (v35.11 최종형) ---

def clean_cell_text(text):
    if not text: return ""
    # 줄바꿈을 공백으로, 다중 공백을 단일 공백으로
    return re.sub(r'\s+', ' ', str(text).replace('\n', ' ')).strip()

def repair_broken_words_in_desc(text):
    """
    텍스트 전략 사용 시 발생하는 분절 현상(Apa * che)을 복구하는 수술 도구
    """
    if not text: return ""
    # 1. 영어/한글 단어 중간에 끼어든 하이픈/공백/* 제거
    text = re.sub(r'([a-zA-Z])\s*-\s*([a-zA-Z])', r'\1\2', text)
    text = re.sub(r'([a-zA-Z])\s*\*\s*([a-zA-Z])', r'\1\2', text)
    text = re.sub(r'([가-힣])\s*\*\s*([가-힣])', r'\1\2', text)
    
    # 2. 괄호 보정
    text = re.sub(r'\(\s+', '(', text)
    text = re.sub(r'\s+\)', ')', text)
    return text

def find_column_separators(page):
    """
    페이지에서 헤더 좌표를 찾아 세로 구분선(Vertical Lines)을 계산
    """
    words = page.extract_words()
    header_map = {}
    
    # 헤더 탐색 범위를 페이지 상단으로 제한하지 않고 전체 스캔하되, y값 비교
    for w in words:
        if w['text'] in ['유형', '기능분류', '요약']:
            # 가장 상단에 등장하는 헤더만 신뢰
            if w['text'] not in header_map:
                header_map[w['text']] = w
            
    # 핵심 헤더 2개가 없으면 좌표 계산 포기
    if '기능분류' not in header_map or '요약' not in header_map:
        return None

    # 좌표 계산
    x_start = 0
    # 유형이 있으면 유형~분류 사이, 없으면 0~분류 사이
    x1 = (header_map['유형']['x1'] + header_map['기능분류']['x0']) / 2 if '유형' in header_map else header_map['기능분류']['x0'] - 10
    
    # 분류~요약 사이 (여기가 제일 중요)
    x2 = (header_map['기능분류']['x1'] + header_map['요약']['x0']) / 2
    
    x_end = page.width
    
    return [x_start, x1, x2, x_end]

def parse_pdf_v35(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        extracted_data = [] 
        
        # 페이지별 순회
        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # --- 전략 수립 ---
            strategies = []
            
            # 1. [스마트 그리드] 헤더 좌표 기반 강제 분할
            separators = find_column_separators(page)
            if separators:
                strategies.append({
                    "name": "explicit",
                    "vertical_strategy": "explicit",
                    "explicit_vertical_lines": separators,
                    "horizontal_strategy": "text",
                    "intersection_y_tolerance": 5
                })
            
            # 2. [물리적 선] 실제 그려진 선이 있는 경우
            strategies.append({
                "name": "lines",
                "vertical_strategy": "lines", 
                "horizontal_strategy": "lines",
                "snap_tolerance": 4
            })
            
            # 3. [텍스트 분포] 선도 없고 헤더도 못 찾았을 때 (최후의 보루)
            #    단, 이 경우 Apa * che 현상이 발생하므로 후처리 필수
            strategies.append({
                "name": "text",
                "vertical_strategy": "text", 
                "horizontal_strategy": "text"
            })
            
            page_extracted = False
            
            for settings in strategies:
                if page_extracted: break # 이미 추출 성공했으면 다음 전략 스킵
                
                try:
                    tables = page.extract_tables(table_settings=settings)
                except:
                    continue

                if not tables: continue

                temp_data = []
                valid_rows = 0

                for table in tables:
                    for row in table:
                        # 데이터 정제
                        cells = [clean_cell_text(c) for c in row]
                        
                        # 최소한의 유효성 검사 (컬럼 수 부족하면 병합 시도 or 스킵)
                        if not cells: continue
                        
                        # 컬럼 매핑 (전략에 따라 인덱스가 다를 수 있음)
                        # 보통 [유형, 분류, 요약, ...] 순서
                        if len(cells) >= 3:
                            v_type = cells[0]
                            v_cat = cells[1]
                            v_desc = cells[2]
                            v_id = cells[3] if len(cells) > 3 else ""
                        elif len(cells) == 2 and settings['name'] == 'text':
                            # 텍스트 전략에서 '유형'과 '분류'가 붙어나온 경우
                            v_type = cells[0] # 여기에 유형+분류가 섞임
                            v_cat = ""
                            v_desc = cells[1]
                            v_id = ""
                        else:
                            continue

                        # 헤더 행 스킵
                        if any(x in v_type for x in ["유형", "구분", "Type"]) and any(x in v_desc for x in ["요약", "Summary"]): 
                            continue

                        target_keywords = ['개선', '신규', '이슈', '수정', 'BUG', 'Feature', '기능']
                        
                        # 내용이 있고, 타입에 키워드가 있을 때 (혹은 타입이 비어있어도 내용이 확실하면)
                        if v_desc and (any(k in v_type for k in target_keywords) or any(k in v_cat for k in target_keywords)):
                            
                            # 1. 불렛 제거
                            clean_desc = re.sub(r'^[•\-o]\s*', '', v_desc)
                            
                            # 2. [필수] 단어 봉합 수술 (어떤 전략이든 안전하게 한 번 돌림)
                            final_desc = repair_broken_words_in_desc(clean_desc)
                            
                            cat_part = f" {v_cat}" if v_cat else ""
                            id_part = f" ({v_id})" if v_id and v_id not in ["-", ""] else ""
                            
                            line_str = f"[{v_type}]{cat_part} * {final_desc}{id_part}"
                            
                            if line_str not in temp_data:
                                temp_data.append(line_str)
                                valid_rows += 1
                
                # 이 전략으로 유의미한 데이터(3행 이상)를 뽑았다면 채택
                if valid_rows > 0:
                    extracted_data.extend(temp_data)
                    page_extracted = True
        
        # 중복 제거 (페이지 넘어가며 중복 추출될 가능성 배제)
        extracted_data = list(dict.fromkeys(extracted_data))

        # 메타데이터 추출 (정규식 강화)
        # 1. 버전: TrusGuard 뒤의 숫자
        v = re.search(r'TrusGuard\s+v?([0-9\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        
        # 2. OpenSSL: "OpenSSL" 문자열이 포함된 줄에서 숫자.숫자.숫자 패턴 찾기
        #    Ex: OpenSSL 업그레이드 1.1.1 -> 3.0.9
        ssl_match = re.search(r'OpenSSL.*?(\d+\.\d+\.\d+[a-z]?)', full_raw, re.I | re.DOTALL)
        openssl = ssl_match.group(1) if ssl_match else "-"
        
        # 3. OpenSSH
        ssh_match = re.search(r'OpenSSH.*?(\d+\.\d+p\d+)', full_raw, re.I | re.DOTALL)
        openssh = ssh_match.group(1) if ssh_match else "-"

    return {
        "version": version,
        "openssl": openssl,
        "openssh": openssh,
        "content": "\n\n".join(extracted_data),
        "raw": full_raw
    }

# --- 4. 사이드바 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v35"

with st.sidebar:
    st.header("📜 버전 히스토리")
    try:
        hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    except:
        hist_df = pd.DataFrame()

    sel_v = st.radio("버전 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 등록", expanded=True):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            if uploaded:
                for f in uploaded:
                    try:
                        info = parse_pdf_v35(f)
                        cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                        if not cursor.fetchone():
                            cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                        (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                            conn.commit()
                            st.success(f"v{info['version']} 저장됨")
                        else:
                            st.warning(f"v{info['version']} 이미 존재")
                    except Exception as e:
                        st.error(f"오류: {e}")
                st.rerun()

    with st.expander("🗑️ 데이터 삭제"):
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전", hist_df['version'].tolist())
            if st.button("🚨 삭제"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

# --- 5. 메인 렌더링 ---
st.title("🛡️ TrusGuard 통합 관제 (v35.11)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def render_report_card(version, openssl, openssh, content, search_kws=None):
    st.markdown(f"<div class='version-header'>📦 TrusGuard {version}</div>", unsafe_allow_html=True)
    with st.container():
        st.markdown("<div class='report-box'>", unsafe_allow_html=True)
        st.markdown(f"<div class='meta-label'>🔒 보안 컴포넌트</div>", unsafe_allow_html=True)
        st.text(f"OpenSSL: {openssl} / OpenSSH: {openssh}")
        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown(f"<div class='meta-label'>📋 상세 변경 내역</div>", unsafe_allow_html=True)
        if content:
            paras = content.split('\n\n')
            has_content = False
            for p in paras:
                if not p.strip(): continue
                display_text = p.strip()
                if search_kws:
                    if not all(k.lower() in display_text.lower() for k in search_kws): continue
                    for k in search_kws:
                        display_text = re.sub(f"({re.escape(k)})", r"<span class='highlight'>\1</span>", display_text, flags=re.I)
                st.markdown(f"<div class='item-box'>{display_text}</div>", unsafe_allow_html=True)
                has_content = True
            
            if not has_content and search_kws:
                st.info("검색 결과가 없습니다.")
        else:
            st.warning("데이터 추출 실패")
        st.markdown("</div>", unsafe_allow_html=True)

if keyword:
    kws = keyword.split()
    query = "SELECT * FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    if res.empty: st.info("검색 결과 없음")
    else:
        for _, row in res.iterrows(): render_report_card(row['version'], row['openssl'], row['openssh'], row['improvements'], kws)
elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    render_report_card(r['version'], r['openssl'], r['openssh'], r['improvements'])
else:
    st.info("좌측 사이드바에서 PDF 파일을 등록하거나 버전을 선택해주세요.")
