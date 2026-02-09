import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 설정 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v35.10", layout="wide")

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

# --- 3. [통합 엔진] Smart Grid 파싱 (v35.10 핵심) ---
def clean_cell_text(text):
    if not text: return ""
    # 줄바꿈을 공백으로, 다중 공백을 단일 공백으로
    return re.sub(r'\s+', ' ', str(text).replace('\n', ' ')).strip()

def find_column_separators(page):
    """
    페이지에서 '유형', '기능분류', '요약' 헤더의 좌표를 찾아
    가장 완벽한 세로 구분선(Vertical Lines) 위치를 계산합니다.
    """
    words = page.extract_words()
    
    # 헤더 단어 찾기
    header_map = {}
    for w in words:
        if w['text'] in ['유형', '기능분류', '요약']:
            header_map[w['text']] = w
            
    if len(header_map) < 3:
        return None # 헤더를 못 찾으면 기본 전략 사용

    # 좌표 계산 (각 헤더의 중간 지점이나 끝 지점을 기준으로 분할)
    # 1. 유형 ~ 기능분류 사이 선
    x1 = (header_map['유형']['x1'] + header_map['기능분류']['x0']) / 2
    
    # 2. 기능분류 ~ 요약 사이 선 (여기가 제일 중요, Apa * che 방지)
    x2 = (header_map['기능분류']['x1'] + header_map['요약']['x0']) / 2
    
    # 3. 요약 끝나는 지점 (페이지 우측 여백 고려)
    x3 = page.width - 20 

    return [0, x1, x2, x3]

def parse_pdf_v35(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        extracted_data = [] 
        
        # 문서 전체의 기본 구분선 좌표 (첫 페이지 등에서 발견 시 저장)
        default_separators = None

        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # 1. 이 페이지에 맞는 '강제 구분선' 찾기
            separators = find_column_separators(page)
            if separators:
                default_separators = separators # 찾았으면 캐싱 (다음 페이지를 위해)
            elif default_separators:
                separators = default_separators # 못 찾았으면 이전 페이지 설정 사용
            
            # 2. 테이블 추출 전략 수립
            settings = {}
            if separators:
                # [핵심] 텍스트가 찢어지지 않게 좌표로 강제 분할 (explicit)
                settings = {
                    "vertical_strategy": "explicit",
                    "explicit_vertical_lines": separators,
                    "horizontal_strategy": "text", # 행은 텍스트 간격으로 구분
                    "intersection_y_tolerance": 5  # 행 높이 관용구
                }
            else:
                # 헤더도 없고 선도 안보이면 'lines' 전략 (기존 방식 fallback)
                settings = {"vertical_strategy": "lines", "horizontal_strategy": "lines"}

            tables = page.extract_tables(table_settings=settings)
            
            if not tables: continue

            last_type = ""
            last_cat = ""
            
            for table in tables:
                for row in table:
                    # 셀 클리닝
                    cells = [clean_cell_text(c) for c in row]
                    
                    # 데이터 검증 (최소 3개 컬럼 필요: 유형, 분류, 요약)
                    if not cells or len(cells) < 3: continue
                    
                    # 헤더 행 스킵
                    if any(x in cells[0] for x in ["유형", "구분", "Type"]) and any(x in cells[1] for x in ["기능분류", "Category"]): continue

                    # 명시적 컬럼 매핑 (좌표로 잘랐으므로 인덱스가 정확함)
                    v_type = cells[0]
                    v_cat = cells[1]
                    v_desc_raw = cells[2]
                    v_id = cells[3] if len(cells) > 3 else ""

                    # Forward Fill (빈칸이면 윗줄 값 가져오기)
                    if v_type: last_type = v_type
                    else: v_type = last_type
                    
                    if v_cat: last_cat = v_cat
                    else: v_cat = last_cat

                    target_keywords = ['개선', '신규', '이슈', '수정', 'BUG', 'Feature']
                    
                    # '내용'이 있고 '타입'이 유효할 때만 처리
                    if v_desc_raw and any(k in v_type for k in target_keywords):
                        
                        # 1. 불렛 제거
                        clean_desc = re.sub(r'^[•\-o]\s*', '', v_desc_raw)
                        
                        # 2. 텍스트 후처리 (AOS 설정) 괄호 보정 등
                        #    Smart Grid를 썼으므로 Apa * che 같은 분절은 이미 사라졌음. 
                        #    괄호 앞뒤 공백만 살짝 다듬어줍니다.
                        clean_desc = re.sub(r'\(\s+', '(', clean_desc)
                        clean_desc = re.sub(r'\s+\)', ')', clean_desc)
                        
                        cat_part = f" {v_cat}" if v_cat else ""
                        id_part = f" ({v_id})" if v_id and v_id not in ["-", ""] else ""
                        
                        # 최종 포맷
                        line_str = f"[{v_type}]{cat_part} * {clean_desc}{id_part}"
                        
                        if line_str not in extracted_data:
                            extracted_data.append(line_str)

        # 메타데이터 추출
        v = re.search(r'TrusGuard\s+v?([\d\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[a-z]?)', full_raw, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_raw, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
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
st.title("🛡️ TrusGuard 통합 관제 (v35.10)")

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
